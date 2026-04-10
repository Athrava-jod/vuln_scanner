"""
╔══════════════════════════════════════════════════════════╗
║   VulnScanX – Web & Port Vulnerability Scanner           ║
║   Flask Application – Main Entry Point (MongoDB)         ║
╚══════════════════════════════════════════════════════════╝
Author  : Engineering Mini-Project
Purpose : Orchestrates all routes, auth, DB (MongoDB), and scan jobs
"""

import os, json, threading
from datetime import datetime
from bson import ObjectId

from flask import (Flask, render_template, request, redirect,
                   url_for, flash, jsonify, send_file)
from flask_login import (LoginManager, UserMixin, login_user,
                          logout_user, login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient

# ──────────────────────────────────────────────────────────────
# App & Config
# ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY']      = os.environ.get('SECRET_KEY', 'vulnscanx-dev-secret-2024')
app.config['MONGO_URI']       = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/vulnscanx')
app.config['REPORTS_FOLDER']  = os.environ.get('REPORTS_FOLDER', os.path.join('static', 'reports'))

# Ensure reports folder exists
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

# MongoDB Initialization
client = MongoClient(app.config['MONGO_URI'])
# Use 'vulnscanx' as the default database if not specified in the URI
try:
    db = client.get_default_database()
except:
    db = client.get_database("vulnscanx")

login_manager = LoginManager(app)

# Custom Jinja2 filter: parse JSON string inside templates
@app.template_filter('fromjson')
def fromjson_filter(s):
    if not s: return []
    if isinstance(s, (list, dict)): return s
    try:    return json.loads(s)
    except: return []

login_manager.login_view             = 'login'
login_manager.login_message          = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

# In-memory progress store  { scan_id: int(0-100) | dict }
scan_progress = {}

# ──────────────────────────────────────────────────────────────
# Database Models (MongoDB Wrapper)
# ──────────────────────────────────────────────────────────────

class User(UserMixin):
    """User object for Flask-Login"""
    def __init__(self, user_data):
        self.id       = str(user_data['_id'])
        self.username = user_data['username']
        self.email    = user_data['email']
        self.password = user_data['password']

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = db.users.find_one({'_id': ObjectId(user_id)})
        return User(user_data) if user_data else None
    except:
        return None

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _update_progress(scan_id, base, ceiling, fraction):
    """Map 0-1 fraction into [base, ceiling] and store it"""
    scan_progress[scan_id] = int(base + (ceiling - base) * fraction)


def _risk_from_cvss(score: float) -> str:
    """Convert numeric CVSS score → human-readable risk band"""
    if score == 0:   return 'Info'
    if score < 4.0:  return 'Low'
    if score < 7.0:  return 'Medium'
    if score < 9.0:  return 'High'
    return 'Critical'


def _is_local_target(target: str) -> bool:
    return os.path.exists(os.path.expanduser(target.strip()))


def run_scan_background(app_ctx, scan_id, target, scan_type, user_id):
    """
    Runs in a daemon thread. Updates scan_progress and writes to MongoDB.
    """
    from scanner.port_scanner import run_port_scan
    from scanner.vuln_scanner import run_vuln_scan
    from scanner.report_gen import generate_pdf_report
    from scanner.cvss import calculate_cvss
    from scanner.malware_scanner import run_malware_scan, summarize_malware_findings

    with app_ctx:
        scan_progress[scan_id] = 5
        open_ports = []
        vulnerabilities = []
        malware_findings = []
        malware_summary = {}
        headers_info = {}
        is_local_target = _is_local_target(target)

        try:
            if scan_type in ('port', 'full') and not is_local_target:
                scan_progress[scan_id] = 10
                open_ports = run_port_scan(
                    target,
                    progress_cb=lambda p: _update_progress(scan_id, 10, 48, p)
                )

            scan_progress[scan_id] = 50

            if scan_type in ('web', 'full') and not is_local_target:
                result = run_vuln_scan(
                    target,
                    progress_cb=lambda p: _update_progress(scan_id, 52, 85, p)
                )
                vulnerabilities = result.get('vulnerabilities', [])
                headers_info = result.get('headers', {})

            scan_progress[scan_id] = 86
            malware_result = run_malware_scan(
                target,
                progress_cb=lambda p: _update_progress(scan_id, 86, 92, p)
            )
            malware_findings = malware_result.get('findings', [])
            malware_summary = malware_result.get('summary', {})
            if malware_summary.get('scanned'):
                malware_summary.update(summarize_malware_findings(malware_findings))

            scan_progress[scan_id] = 93
            cvss_score = calculate_cvss(vulnerabilities + malware_findings, open_ports)
            risk_level = _risk_from_cvss(cvss_score)

            scan_progress[scan_id] = 95
            
            # Record dictionary for MongoDB
            record = {
                'target': target,
                'scan_type': scan_type,
                'risk_level': risk_level,
                'cvss_score': round(cvss_score, 1),
                'open_ports': open_ports,
                'vulnerabilities': vulnerabilities,
                'malware_findings': malware_findings,
                'malware_summary': malware_summary,
                'headers_info': headers_info,
                'user_id': ObjectId(user_id),
                'created_at': datetime.utcnow(),
                'report_path': None
            }
            
            result = db.scans.insert_one(record)
            record_id = str(result.inserted_id)

            scan_progress[scan_id] = 97
            os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
            pdf_filename = f"report_{record_id}_{int(datetime.utcnow().timestamp())}.pdf"
            pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
            
            # Since generate_pdf_report might expect a class, we pass the dict
            # We might need to wrap it or modify generate_pdf_report. 
            # For simplicity, we add 'id' to the dict for the generator.
            record['id'] = record_id
            from types import SimpleNamespace
            obj_record = SimpleNamespace(**record)
            generate_pdf_report(obj_record, pdf_path)
            
            db.scans.update_one({'_id': ObjectId(record_id)}, {'$set': {'report_path': pdf_path}})

            scan_progress[scan_id] = {'done': True, 'record_id': record_id}

        except Exception as exc:
            import traceback
            traceback.print_exc()
            scan_progress[scan_id] = {'done': True, 'error': str(exc)}

# Routes – Public
# ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        errors = []
        if not all([username, email, password, confirm]):
            errors.append('All fields are required.')
        if password != confirm:
            errors.append('Passwords do not match.')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if db.users.find_one({'username': username}):
            errors.append('Username already taken.')
        if db.users.find_one({'email': email}):
            errors.append('Email already registered.')

        for e in errors:
            flash(e, 'danger')

        if not errors:
            user_data = {
                'username': username,
                'email': email,
                'password': generate_password_hash(password),
                'created_at': datetime.utcnow()
            }
            db.users.insert_one(user_data)
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user_data = db.users.find_one({'username': username})

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user, remember=bool(request.form.get('remember')))
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))


# ──────────────────────────────────────────────────────────────
# Routes – Protected
# ──────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    scans_cursor = db.scans.find({'user_id': ObjectId(current_user.id)}).sort('created_at', -1)
    scans = []
    for s in scans_cursor:
        s['id'] = str(s['_id'])
        scans.append(s)
        
    totals = dict(
        total    = len(scans),
        critical = sum(1 for s in scans if s.get('risk_level') == 'Critical'),
        high     = sum(1 for s in scans if s.get('risk_level') == 'High'),
        medium   = sum(1 for s in scans if s.get('risk_level') == 'Medium'),
        low      = sum(1 for s in scans if s.get('risk_level') in ('Low', 'Info')),
    )
    return render_template('dashboard.html', scans=scans, **totals)


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        target    = request.form.get('target', '').strip()
        scan_type = request.form.get('scan_type', 'full')
        agreed    = request.form.get('agreed')

        if not target:
            flash('Target URL or IP is required.', 'danger')
            return redirect(url_for('scan'))
        if not agreed:
            flash('You must confirm you have permission to scan this target.', 'warning')
            return redirect(url_for('scan'))

        scan_id = f"{current_user.id}_{int(datetime.utcnow().timestamp())}"
        scan_progress[scan_id] = 0

        t = threading.Thread(
            target=run_scan_background,
            args=(app.app_context(), scan_id, target, scan_type, current_user.id),
            daemon=True,
        )
        t.start()
        return redirect(url_for('progress', scan_id=scan_id))

    return render_template('scan.html')


@app.route('/progress/<scan_id>')
@login_required
def progress(scan_id):
    """Renders the animated progress page; JS polls /api/progress/<scan_id>"""
    return render_template('progress.html', scan_id=scan_id)


@app.route('/api/progress/<scan_id>')
@login_required
def api_progress(scan_id):
    """JSON endpoint – returns integer progress or completion dict"""
    status = scan_progress.get(scan_id, 0)
    if isinstance(status, dict):
        return jsonify(status)
    return jsonify({'progress': status})


@app.route('/results/<record_id>')
@login_required
def results(record_id):
    try:
        record = db.scans.find_one({'_id': ObjectId(record_id), 'user_id': ObjectId(current_user.id)})
    except:
        return "Invalid ID Format", 400
        
    if not record:
        return "Not Found", 404
    
    record['id'] = str(record['_id'])
    
    return render_template('results.html',
                           record=record, 
                           ports=record.get('open_ports', []),
                           vulns=record.get('vulnerabilities', []), 
                           malware=record.get('malware_findings', []),
                           malware_summary=record.get('malware_summary', {}), 
                           headers=record.get('headers_info', {}))


@app.route('/report/<record_id>')
@login_required
def report(record_id):
    try:
        record = db.scans.find_one({'_id': ObjectId(record_id), 'user_id': ObjectId(current_user.id)})
    except:
        return "Invalid ID Format", 400
        
    if not record:
        return "Not Found", 404
        
    if not record.get('report_path') or not os.path.exists(record['report_path']):
        from scanner.report_gen import generate_pdf_report
        os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
        pdf_filename = f"report_{record_id}_{int(datetime.utcnow().timestamp())}.pdf"
        pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
        
        record['id'] = str(record['_id'])
        from types import SimpleNamespace
        obj_record = SimpleNamespace(**record)
        generate_pdf_report(obj_record, pdf_path)
        
        db.scans.update_one({'_id': ObjectId(record_id)}, {'$set': {'report_path': pdf_path}})
        report_file = pdf_path
    else:
        report_file = record['report_path']

    return send_file(report_file, as_attachment=True,
                     download_name=f'vulnscanx_report_{record_id}.pdf')


@app.route('/delete/<record_id>', methods=['POST'])
@login_required
def delete_scan(record_id):
    try:
        record = db.scans.find_one({'_id': ObjectId(record_id), 'user_id': ObjectId(current_user.id)})
    except:
        return "Invalid ID Format", 400
        
    if not record:
        return "Not Found", 404
        
    if record.get('report_path') and os.path.exists(record['report_path']):
        os.remove(record['report_path'])
    
    db.scans.delete_one({'_id': ObjectId(record_id)})
    flash('Scan record deleted.', 'info')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
