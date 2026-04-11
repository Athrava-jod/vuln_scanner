# VulnScanX – Web & Port Vulnerability Scanner

A full-stack, production-ready Flask application for automated web
vulnerability assessment and port scanning. Built as an engineering
mini-project with advanced features including nmap integration, multi-
threaded scanning, CVSS scoring, and PDF report generation.

---

## Project Structure

```
vuln_scanner/
├── app.py                  ← Flask app: routes, auth, DB, scan threading
├── requirements.txt        ← Python dependencies
├── Procfile                ← Heroku/Render process file
├── render.yaml             ← Render auto-deploy config
├── README.md               ← This file
│
├── scanner/
│   ├── __init__.py
│   ├── port_scanner.py     ← nmap-based port scanner (socket fallback)
│   ├── vuln_scanner.py     ← SQLi/XSS/redirect/header checks
│   ├── cvss.py             ← CVSS score calculation
│   └── report_gen.py       ← PDF report generator (ReportLab)
│
├── templates/
│   ├── base.html           ← Shared layout, navbar, flash messages
│   ├── index.html          ← Landing page with terminal animation
│   ├── login.html          ← Login form
│   ├── register.html       ← Registration form
│   ├── dashboard.html      ← Scan history + stats
│   ├── scan.html           ← Scan configuration
│   ├── progress.html       ← Live progress bar (JS polling)
│   └── results.html        ← Detailed results with accordion
│
├── static/
│   ├── css/style.css       ← Dark cyberpunk theme
│   └── reports/            ← Generated PDFs (auto-created)
│
└── instance/
    └── vulnscanx.db        ← SQLite database (auto-created)
```

---

## Setup Instructions (Local)

### Step 1 – Install nmap

```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# Windows – download from https://nmap.org/download.html
```

### Step 2 – Create virtual environment

```bash
cd vuln_scanner
python -m venv venv
source venv/bin/activate     # Linux/macOS
venv\Scripts\activate        # Windows
```

### Step 3 – Install Python dependencies

```bash
pip install -r requirements.txt
```

### Step 4 – Run

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

### Step 5 – Register an account and start scanning!

---

## How Each Vulnerability Check Works

### SQL Injection
The scanner finds all HTML forms on the target page, fills every text
input with classic SQLi payloads (`'`, `' OR '1'='1`, `"; DROP TABLE--`),
submits the form, and inspects the response body for database error
signatures (MySQL, PostgreSQL, MSSQL errors). URL query parameters are
also tested. Error-based detection confirms unsanitised input reaches the
database layer.

### Cross-Site Scripting (XSS)
The payload `<script>alert('xss')</script>` is injected into all form
fields. If the raw unescaped string appears in the HTML response, the
application reflects user input without proper output encoding — a
reflected XSS vulnerability.

### Open Redirect
Common redirect parameter names (`redirect`, `url`, `next`, `returnUrl`,
`goto`) are probed by appending `?param=https://evil.example.com` to the
URL. If the server returns a 3xx redirect with the injected domain in the
`Location` header, an open redirect exists.

### Missing Security Headers
A GET request is made to the target and six critical HTTP security headers
are checked: `Content-Security-Policy`, `X-Frame-Options`,
`X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`,
and `Permissions-Policy`. Missing headers are flagged as Low severity
findings.

### Port Scanning
Primary: `python-nmap` calls `nmap -sV -T4 -Pn` for service/version
detection. Fallback (if nmap not installed): Python `socket.connect_ex()`
is called concurrently via `ThreadPoolExecutor` with 50 threads — scanning
20 ports in parallel instead of sequentially, reducing wall-clock time by
~20x.

### CVSS Score
A simplified CVSS v3.1-inspired heuristic: the highest severity finding
anchors the score; each additional finding adds 15% of its weight; open
risky ports (Telnet, RDP, Redis, etc.) add a 20% bonus. Final score is
clamped to [0–10] and mapped to Info/Low/Medium/High/Critical.

-

## Legal Notice

VulnScanX is for educational purposes and authorised security testing ONLY.
Scanning systems without explicit permission is illegal under the Computer
Fraud and Abuse Act, Computer Misuse Act, and similar laws worldwide. The
authors accept no liability for misuse.

## Malware Detection Module

VulnScanX now includes a local malware detection pipeline for file or directory targets. It combines bundled YARA rules, hash matching, signature matching, and heuristic analysis to detect Trojan, Worm, Ransomware, Rootkit, Spyware, and Keylogger indicators. If yara-python is not available at runtime, the app falls back to its built-in parser for the bundled rules.

