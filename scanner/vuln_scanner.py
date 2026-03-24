"""
scanner/vuln_scanner.py
────────────────────────
Web vulnerability scanner using requests + BeautifulSoup.

Checks performed (with explanations):
───────────────────────────────────────
1. SQL Injection (SQLi)
   ─ Appends classic SQLi payloads (' OR '1'='1, etc.) to form fields
     and URL parameters. Looks for database error strings in the response.
   ─ Error-based detection: MySQL/PostgreSQL/MSSQL error messages
     appearing in the page body indicate unsanitised input reaches the DB.

2. Cross-Site Scripting (XSS)
   ─ Injects a harmless XSS marker (<script>alert('xss')</script>) into
     form fields. If the raw string is reflected unescaped in the response,
     the field is vulnerable to reflected XSS.

3. Open Redirect
   ─ Checks URL parameters named 'redirect', 'url', 'next', etc. by
     injecting an external domain. If the response Location header or
     body contains the injected domain, an open redirect exists.

4. Missing Security Headers
   ─ Verifies the presence of:
       • Content-Security-Policy (CSP)
       • X-Frame-Options
       • X-Content-Type-Options
       • Strict-Transport-Security (HSTS)
       • Referrer-Policy
       • Permissions-Policy
     Missing headers allow clickjacking, MIME sniffing, etc.

5. Sensitive File Exposure
   ─ Probes for commonly-exposed files (.env, robots.txt, /admin, etc.)
     and flags any that return a 200 status code.
"""

import re
import requests
from bs4 import BeautifulSoup
from typing import Callable, Dict, List
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

# ── Config ─────────────────────────────────────────────────────────────────────
TIMEOUT    = 8      # seconds per HTTP request
USER_AGENT = 'Mozilla/5.0 VulnScanX/1.0 (Educational Security Scanner)'
HEADERS    = {'User-Agent': USER_AGENT}

# ── SQLi payloads & error signatures ──────────────────────────────────────────
SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "' OR '1'='1' --", "1; DROP TABLE users--"]
SQLI_ERRORS   = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "ora-01756",
    "microsoft ole db provider for odbc drivers error",
    "syntax error",
    "mysql_fetch",
]

# ── XSS payloads ──────────────────────────────────────────────────────────────
XSS_PAYLOAD = "<script>alert('xss')</script>"

# ── Open redirect params ───────────────────────────────────────────────────────
REDIRECT_PARAMS  = ['redirect', 'url', 'next', 'return', 'returnUrl', 'goto', 'redir']
REDIRECT_PROBE   = 'https://evil.example.com'

# ── Security headers to check ─────────────────────────────────────────────────
SECURITY_HEADERS = {
    'Content-Security-Policy':   'Prevents XSS by restricting resource origins.',
    'X-Frame-Options':           'Prevents clickjacking by disallowing iframe embedding.',
    'X-Content-Type-Options':    'Stops MIME-type sniffing attacks.',
    'Strict-Transport-Security': 'Forces HTTPS connections (HSTS).',
    'Referrer-Policy':           'Controls how much referrer info is shared.',
    'Permissions-Policy':        'Controls browser feature permissions.',
}

# ── Sensitive paths to probe ───────────────────────────────────────────────────
SENSITIVE_PATHS = [
    '/.env', '/.git/config', '/config.php', '/wp-config.php',
    '/admin', '/administrator', '/robots.txt', '/sitemap.xml',
    '/phpinfo.php', '/.htaccess', '/backup.zip', '/db.sql',
]


def run_vuln_scan(target: str, progress_cb: Callable = None) -> Dict:
    """
    Main entry point.
    Returns:
      {
        'vulnerabilities': [ {name, severity, description, evidence} … ],
        'headers':         { header_name: value | 'MISSING' … }
      }
    """
    base_url      = _normalize_url(target)
    vulnerabilities: List[Dict] = []
    total_steps   = 5
    step          = 0

    def tick():
        nonlocal step
        step += 1
        if progress_cb:
            progress_cb(step / total_steps)

    session = requests.Session()
    session.headers.update(HEADERS)

    # ── 1. Fetch the page & collect forms ─────────────────────────────────────
    try:
        resp = session.get(base_url, timeout=TIMEOUT, verify=False,
                           allow_redirects=True)
        soup = BeautifulSoup(resp.text, 'html.parser')
    except requests.RequestException as e:
        return {'vulnerabilities': [_make_vuln(
            'Connection Error', 'Info',
            f'Could not reach {base_url}: {e}', '')], 'headers': {}}
    tick()

    # ── 2. SQL Injection ──────────────────────────────────────────────────────
    sqli_findings = _check_sqli(session, base_url, soup)
    vulnerabilities.extend(sqli_findings)
    tick()

    # ── 3. XSS ────────────────────────────────────────────────────────────────
    xss_findings = _check_xss(session, base_url, soup)
    vulnerabilities.extend(xss_findings)
    tick()

    # ── 4. Open Redirect ──────────────────────────────────────────────────────
    redirect_findings = _check_open_redirect(session, base_url)
    vulnerabilities.extend(redirect_findings)
    tick()

    # ── 5. Security Headers + Sensitive Files ─────────────────────────────────
    headers_result, header_findings = _check_headers(resp)
    vulnerabilities.extend(header_findings)
    file_findings = _check_sensitive_files(session, base_url)
    vulnerabilities.extend(file_findings)
    tick()

    return {'vulnerabilities': vulnerabilities, 'headers': headers_result}


# ──────────────────────────────────────────────────────────────────────────────
# Individual Check Functions
# ──────────────────────────────────────────────────────────────────────────────

def _check_sqli(session, base_url: str, soup) -> List[Dict]:
    """
    Finds all <form> elements, submits each with SQLi payloads in every
    text/search/email input field, then checks the response body for
    database error messages.
    """
    findings = []
    forms    = soup.find_all('form')

    for form in forms:
        action  = urljoin(base_url, form.get('action') or '')
        method  = (form.get('method') or 'get').lower()
        inputs  = form.find_all(['input', 'textarea'])

        for payload in SQLI_PAYLOADS:
            data = {}
            for inp in inputs:
                name = inp.get('name') or inp.get('id') or 'field'
                itype = inp.get('type', 'text').lower()
                if itype in ('text', 'search', 'email', 'password', 'number', ''):
                    data[name] = payload
                elif itype == 'hidden':
                    data[name] = inp.get('value', '')

            try:
                if method == 'post':
                    r = session.post(action, data=data, timeout=TIMEOUT, verify=False)
                else:
                    r = session.get(action, params=data, timeout=TIMEOUT, verify=False)

                body_lower = r.text.lower()
                for err in SQLI_ERRORS:
                    if err in body_lower:
                        findings.append(_make_vuln(
                            'SQL Injection', 'Critical',
                            f'Database error detected after injecting payload into form at {action}.',
                            f'Payload: {payload!r} → Error: "{err}"'
                        ))
                        return findings  # one confirmed finding is enough
            except Exception:
                pass

    # Also test URL parameters
    parsed = urlparse(base_url)
    qs     = parse_qs(parsed.query)
    for key in qs:
        for payload in SQLI_PAYLOADS[:2]:
            test_params = {k: (payload if k == key else v[0]) for k, v in qs.items()}
            test_url    = urlunparse(parsed._replace(query=urlencode(test_params)))
            try:
                r = session.get(test_url, timeout=TIMEOUT, verify=False)
                body_lower = r.text.lower()
                for err in SQLI_ERRORS:
                    if err in body_lower:
                        findings.append(_make_vuln(
                            'SQL Injection (URL Param)', 'Critical',
                            f'Database error in URL parameter "{key}".',
                            f'Payload: {payload!r}'
                        ))
                        return findings
            except Exception:
                pass

    return findings


def _check_xss(session, base_url: str, soup) -> List[Dict]:
    """
    Submits XSS payload to form fields.
    If the raw payload is reflected verbatim in the HTML response,
    the application is likely vulnerable to reflected XSS.
    """
    findings = []
    forms    = soup.find_all('form')

    for form in forms:
        action = urljoin(base_url, form.get('action') or '')
        method = (form.get('method') or 'get').lower()
        inputs = form.find_all(['input', 'textarea'])

        data = {}
        for inp in inputs:
            name  = inp.get('name') or inp.get('id') or 'field'
            itype = inp.get('type', 'text').lower()
            if itype not in ('submit', 'reset', 'button', 'image', 'file', 'checkbox', 'radio'):
                data[name] = XSS_PAYLOAD

        if not data:
            continue

        try:
            if method == 'post':
                r = session.post(action, data=data, timeout=TIMEOUT, verify=False)
            else:
                r = session.get(action, params=data, timeout=TIMEOUT, verify=False)

            # Unescaped reflection = XSS
            if XSS_PAYLOAD in r.text:
                findings.append(_make_vuln(
                    'Cross-Site Scripting (XSS)', 'High',
                    f'Reflected XSS found: form at {action} reflects input without sanitisation.',
                    f'Payload reflected: {XSS_PAYLOAD!r}'
                ))
        except Exception:
            pass

    return findings


def _check_open_redirect(session, base_url: str) -> List[Dict]:
    """
    Appends each known redirect parameter with an external URL.
    If the server returns a 3xx redirect to that URL, it's an open redirect.
    """
    findings = []

    for param in REDIRECT_PARAMS:
        test_url = f"{base_url}?{param}={REDIRECT_PROBE}"
        try:
            r = session.get(test_url, timeout=TIMEOUT, verify=False,
                            allow_redirects=False)
            loc = r.headers.get('Location', '')
            if r.status_code in (301, 302, 303, 307, 308) and REDIRECT_PROBE in loc:
                findings.append(_make_vuln(
                    'Open Redirect', 'Medium',
                    f'Parameter "{param}" redirects to an attacker-controlled URL.',
                    f'Location: {loc}'
                ))
        except Exception:
            pass

    return findings


def _check_headers(resp) -> (Dict, List[Dict]):
    """
    Checks HTTP response headers against SECURITY_HEADERS.
    Returns (headers_dict, list_of_findings).
    """
    findings      = []
    headers_result = {}
    resp_headers  = {k.lower(): v for k, v in resp.headers.items()}

    for header, explanation in SECURITY_HEADERS.items():
        key    = header.lower()
        value  = resp_headers.get(key, 'MISSING')
        headers_result[header] = value

        if value == 'MISSING':
            findings.append(_make_vuln(
                f'Missing Header: {header}', 'Low',
                explanation,
                f'Header "{header}" was not found in the server response.'
            ))

    return headers_result, findings


def _check_sensitive_files(session, base_url: str) -> List[Dict]:
    """
    Probes common sensitive paths.  A 200 response is a finding.
    """
    findings = []

    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        try:
            r = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 10:
                findings.append(_make_vuln(
                    'Sensitive File Exposure', 'Medium',
                    f'Sensitive path accessible: {path}',
                    f'URL: {url}  Status: {r.status_code}'
                ))
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_vuln(name: str, severity: str, description: str, evidence: str) -> Dict:
    return {
        'name':        name,
        'severity':    severity,      # Critical / High / Medium / Low / Info
        'description': description,
        'evidence':    evidence,
    }


def _normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    return target
