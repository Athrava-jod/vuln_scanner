"""
╔══════════════════════════════════════════════════════════╗
║   VulnScanX – Web & Port Vulnerability Scanner           ║
║   Flask Application – Main Entry Point                   ║
╚══════════════════════════════════════════════════════════╝
Author  : Engineering Mini-Project
Purpose : Orchestrates all routes, auth, DB, and scan jobs
"""

import os, json, threading
from datetime import datetime

from flask import (Flask, render_template, request, redirect,
                   url_for, flash, jsonify, send_file)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                          logout_user, login_required, current_user)
from sqlalchemy import inspect, text
from werkzeug.security import generate_password_hash, check_password_hash

# ──────────────────────────────────────────────────────────────
# App & Config
# ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY']                     = os.environ.get('SECRET_KEY', 'vulnscanx-dev-secret-2024')
app.config['SQLALCHEMY_DATABASE_URI']        = 'sqlite:///vulnscanx.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REPORTS_FOLDER']                 = os.path.join('static', 'reports')

db            = SQLAlchemy(app)
login_manager = LoginManager(app)

# Custom Jinja2 filter: parse JSON string inside templates
import json as _json
@app.template_filter('fromjson')
def fromjson_filter(s):
    try:   return _json.loads(s)
    except: return []
login_manager.login_view             = 'login'
login_manager.login_message          = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

# In-memory progress store  { scan_id: int(0-100) | dict }
scan_progress = {}

# ──────────────────────────────────────────────────────────────
# Database Models
# ──────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    """Admin / User account model"""
    __tablename__ = 'users'
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(80),  unique=True, nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password   = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans      = db.relationship('ScanResult', backref='owner', lazy=True)


class ScanResult(db.Model):
    """Stores results for every completed scan"""
    __tablename__ = 'scan_results'
    id              = db.Column(db.Integer, primary_key=True)
    target          = db.Column(db.String(255), nullable=False)
    scan_type       = db.Column(db.String(20))            # port | web | full
    risk_level      = db.Column(db.String(20))            # Low / Medium / High / Critical
    cvss_score      = db.Column(db.Float, default=0.0)
    open_ports      = db.Column(db.Text, default='[]')    # JSON list
    vulnerabilities = db.Column(db.Text, default='[]')    # JSON list
    malware_findings = db.Column(db.Text, default='[]')   # JSON list
    malware_summary  = db.Column(db.Text, default='{}')   # JSON dict
    headers_info    = db.Column(db.Text, default='{}')    # JSON dict
    report_path     = db.Column(db.String(255))
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    user_id         = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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


def _ensure_scan_result_columns():
    """Backfill new columns for existing SQLite databases."""
    wanted = {
        'malware_findings': "ALTER TABLE scan_results ADD COLUMN malware_findings TEXT DEFAULT '[]'",
        'malware_summary': "ALTER TABLE scan_results ADD COLUMN malware_summary TEXT DEFAULT '{}'",
    }
    existing = {col['name'] for col in inspect(db.engine).get_columns('scan_results')}
    for column_name, ddl in wanted.items():
        if column_name not in existing:
            db.session.execute(text(ddl))
    db.session.commit()


def _is_local_target(target: str) -> bool:
    return os.path.exists(os.path.expanduser(target.strip()))


def run_scan_background(app_ctx, scan_id, target, scan_type, user_id):
    """
    Runs in a daemon thread.
    1. Port scan  (nmap wrapper)
    2. Vuln scan  (requests + BeautifulSoup)
    3. CVSS score calculation
    4. DB write
    5. PDF report generation
    Updates scan_progress[scan_id] throughout so the frontend
    progress bar stays live.
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
            record = ScanResult(
                target=target,
                scan_type=scan_type,
                risk_level=risk_level,
                cvss_score=round(cvss_score, 1),
                open_ports=json.dumps(open_ports),
                vulnerabilities=json.dumps(vulnerabilities),
                malware_findings=json.dumps(malware_findings),
                malware_summary=json.dumps(malware_summary),
                headers_info=json.dumps(headers_info),
                user_id=user_id,
            )
            db.session.add(record)
            db.session.commit()

            scan_progress[scan_id] = 97
            os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
            pdf_filename = f"report_{record.id}_{int(datetime.utcnow().timestamp())}.pdf"
            pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
            generate_pdf_report(record, pdf_path)
            record.report_path = pdf_path
            db.session.commit()

            scan_progress[scan_id] = {'done': True, 'record_id': record.id}

        except Exception as exc:
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
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        for e in errors:
            flash(e, 'danger')

        if not errors:
            user = User(username=username, email=email,
                        password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
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
        user     = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
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
    scans  = ScanResult.query.filter_by(user_id=current_user.id)\
                             .order_by(ScanResult.created_at.desc()).all()
    totals = dict(
        total    = len(scans),
        critical = sum(1 for s in scans if s.risk_level == 'Critical'),
        high     = sum(1 for s in scans if s.risk_level == 'High'),
        medium   = sum(1 for s in scans if s.risk_level == 'Medium'),
        low      = sum(1 for s in scans if s.risk_level in ('Low', 'Info')),
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


@app.route('/results/<int:record_id>')
@login_required
def results(record_id):
    record  = ScanResult.query.filter_by(id=record_id, user_id=current_user.id).first_or_404()
    ports   = json.loads(record.open_ports      or '[]')
    vulns   = json.loads(record.vulnerabilities or '[]')
    malware = json.loads(record.malware_findings or '[]')
    malware_summary = json.loads(record.malware_summary or '{}')
    headers = json.loads(record.headers_info    or '{}')
    return render_template('results.html',
                           record=record, ports=ports,
                           vulns=vulns, malware=malware,
                           malware_summary=malware_summary, headers=headers)


@app.route('/report/<int:record_id>')
@login_required
def report(record_id):
    from scanner.report_gen import generate_pdf_report

    record = ScanResult.query.filter_by(id=record_id, user_id=current_user.id).first_or_404()
    if not record.report_path or not os.path.exists(record.report_path):
        os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
        pdf_filename = f"report_{record.id}_{int(datetime.utcnow().timestamp())}.pdf"
        pdf_path = os.path.join(app.config['REPORTS_FOLDER'], pdf_filename)
        generate_pdf_report(record, pdf_path)
        record.report_path = pdf_path
        db.session.commit()

    return send_file(record.report_path, as_attachment=True,
                     download_name=f'vulnscanx_report_{record_id}.pdf')


@app.route('/delete/<int:record_id>', methods=['POST'])
@login_required
def delete_scan(record_id):
    record = ScanResult.query.filter_by(id=record_id, user_id=current_user.id).first_or_404()
    if record.report_path and os.path.exists(record.report_path):
        os.remove(record.report_path)
    db.session.delete(record)
    db.session.commit()
    flash('Scan record deleted.', 'info')
    return redirect(url_for('dashboard'))


# ──────────────────────────────────────────────────────────────
# Init DB & run
# ──────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()
    _ensure_scan_result_columns()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
