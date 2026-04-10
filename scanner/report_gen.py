"""
scanner/report_gen.py
Generates a professional PDF report using reportlab.
"""

import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
from reportlab.lib.enums import TA_CENTER

C_DARK = colors.HexColor('#0d1117')
C_ACCENT = colors.HexColor('#00d4aa')
C_RED = colors.HexColor('#ff4444')
C_ORANGE = colors.HexColor('#ff8800')
C_YELLOW = colors.HexColor('#ffcc00')
C_GREEN = colors.HexColor('#00cc66')
C_BLUE = colors.HexColor('#3399ff')
C_GRAY = colors.HexColor('#888888')
C_LIGHT = colors.HexColor('#f4f4f4')
C_WHITE = colors.white

SEVERITY_COLORS = {
    'Critical': C_RED,
    'High': C_ORANGE,
    'Medium': C_YELLOW,
    'Low': C_GREEN,
    'Info': C_BLUE,
}


def generate_pdf_report(record, output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2.5 * cm,
    )

    styles = getSampleStyleSheet()
    story = []

    def _safe_load(data, default):
        if isinstance(data, (list, dict)):
            return data
        try:
            return json.loads(data or ( '[]' if isinstance(default, list) else '{}' ))
        except:
            return default

    ports = _safe_load(record.open_ports, [])
    vulns = _safe_load(record.vulnerabilities, [])
    malware = _safe_load(getattr(record, 'malware_findings', []), [])
    malware_summary = _safe_load(getattr(record, 'malware_summary', {}), {})
    hdrs = _safe_load(record.headers_info, {})

    title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=28, textColor=C_ACCENT, alignment=TA_CENTER, spaceAfter=6)
    sub_style = ParagraphStyle('Sub', parent=styles['Normal'], fontSize=12, textColor=C_GRAY, alignment=TA_CENTER, spaceAfter=4)
    h1_style = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=16, textColor=C_ACCENT, spaceBefore=16, spaceAfter=8)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, leading=14, textColor=C_DARK, spaceAfter=4)

    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph('VulnScanX', title_style))
    story.append(Paragraph('Web, Port, and Malware Assessment Report', sub_style))
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width='100%', thickness=2, color=C_ACCENT))
    story.append(Spacer(1, 1 * cm))

    risk_color = SEVERITY_COLORS.get(record.risk_level, C_GRAY)
    cover_data = [
        ['Target', record.target],
        ['Scan Type', record.scan_type.upper()],
        ['Date', record.created_at.strftime('%Y-%m-%d %H:%M UTC')],
        ['Risk Level', record.risk_level],
        ['CVSS Score', f'{record.cvss_score} / 10.0'],
        ['Web Findings', str(len(vulns))],
        ['Malware Findings', str(len(malware))],
    ]
    cover_tbl = Table(cover_data, colWidths=[4 * cm, 12 * cm])
    cover_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), C_LIGHT),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, C_GRAY),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [C_WHITE, C_LIGHT]),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('TEXTCOLOR', (1, 3), (1, 3), risk_color),
        ('FONTNAME', (1, 3), (1, 3), 'Helvetica-Bold'),
    ]))
    story.append(cover_tbl)
    story.append(PageBreak())

    story.append(Paragraph('Open Ports', h1_style))
    story.append(HRFlowable(width='100%', thickness=1, color=C_ACCENT))
    story.append(Spacer(1, 0.3 * cm))
    open_ports = [p for p in ports if p.get('state') == 'open']
    if open_ports:
        port_data = [['Port', 'Service', 'Version', 'State', 'Risk']]
        for p in open_ports:
            port_data.append([str(p['port']), p.get('service', ''), p.get('version', '-') or '-', p.get('state', ''), p.get('risk', '')])
        pt = Table(port_data, colWidths=[2 * cm, 3 * cm, 5.5 * cm, 2.5 * cm, 3 * cm])
        pt.setStyle(_table_base())
        story.append(pt)
    else:
        story.append(Paragraph('No open ports detected.', body_style))

    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph('Web Vulnerability Findings', h1_style))
    story.append(HRFlowable(width='100%', thickness=1, color=C_ACCENT))
    story.append(Spacer(1, 0.3 * cm))
    if vulns:
        _append_findings_table(story, vulns)
    else:
        story.append(Paragraph('No web vulnerabilities detected.', body_style))

    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph('Malware Detection Findings', h1_style))
    story.append(HRFlowable(width='100%', thickness=1, color=C_ACCENT))
    story.append(Spacer(1, 0.3 * cm))
    if malware_summary.get('scanned'):
        summary_rows = [
            ['Engine', malware_summary.get('engine', 'unknown')],
            ['Files Scanned', str(malware_summary.get('files_scanned', 0))],
            ['Highest Severity', malware_summary.get('highest_severity', 'Info')],
            ['Families', ', '.join(f"{k}:{v}" for k, v in malware_summary.get('families', {}).items()) or 'None'],
        ]
        summary_table = Table(summary_rows, colWidths=[4 * cm, 12 * cm])
        summary_table.setStyle(_table_base())
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * cm))
    else:
        story.append(Paragraph(malware_summary.get('reason', 'Malware detection did not run.'), body_style))
    if malware:
        _append_findings_table(story, malware, malware_mode=True)
    else:
        story.append(Paragraph('No malware indicators detected.', body_style))

    story.append(PageBreak())
    story.append(Paragraph('HTTP Security Headers', h1_style))
    story.append(HRFlowable(width='100%', thickness=1, color=C_ACCENT))
    story.append(Spacer(1, 0.3 * cm))
    if hdrs:
        hdr_data = [['Header', 'Status / Value']]
        for name, val in hdrs.items():
            hdr_data.append([name, val])
        ht = Table(hdr_data, colWidths=[7 * cm, 9 * cm])
        ht_style = _table_base()
        for row_idx, (name, val) in enumerate(hdrs.items(), 1):
            if val == 'MISSING':
                ht_style.add('TEXTCOLOR', (1, row_idx), (1, row_idx), C_RED)
                ht_style.add('FONTNAME', (1, row_idx), (1, row_idx), 'Helvetica-Bold')
        ht.setStyle(ht_style)
        story.append(ht)
    else:
        story.append(Paragraph('Header information not available.', body_style))

    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph('Recommendations', h1_style))
    story.append(HRFlowable(width='100%', thickness=1, color=C_ACCENT))
    story.append(Spacer(1, 0.3 * cm))
    for rec in _build_recommendations(vulns, malware, open_ports, hdrs):
        story.append(Paragraph(f'- {rec}', body_style))

    story.append(Spacer(1, 0.8 * cm))
    story.append(HRFlowable(width='100%', thickness=1, color=C_GRAY))
    disclaimer = (
        '<b>Disclaimer:</b> This report was generated by VulnScanX for '
        'educational purposes only. Scanning systems without explicit '
        'authorisation is illegal. The authors accept no liability for '
        'misuse of this tool or the information contained in this report.'
    )
    story.append(Paragraph(disclaimer, ParagraphStyle('disc', parent=body_style, fontSize=8, textColor=C_GRAY)))

    doc.build(story, onFirstPage=_add_page_header, onLaterPages=_add_page_header)


def _append_findings_table(story, findings, malware_mode=False):
    for idx, item in enumerate(findings, 1):
        sev = item.get('severity', 'Info')
        sev_color = SEVERITY_COLORS.get(sev, C_GRAY)
        label = item.get('name', 'Unknown')
        if malware_mode:
            label = f"{item.get('family', 'Malware')} - {label}"
        header_data = [[f"{idx}. {label}", f"[{sev}]"]]
        ht = Table(header_data, colWidths=[13.5 * cm, 2.5 * cm])
        ht.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), C_DARK),
            ('TEXTCOLOR', (0, 0), (0, 0), C_WHITE),
            ('TEXTCOLOR', (1, 0), (1, 0), sev_color),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ]))
        story.append(ht)

        detail_rows = [
            ['Description', item.get('description', '')],
            ['Evidence', item.get('evidence', 'N/A')],
            ['Solution', _solution_for_finding(item, malware_mode=malware_mode)],
        ]
        if malware_mode:
            detail_rows.insert(0, ['Detection Type', item.get('detection_type', 'unknown').upper()])
            detail_rows.insert(1, ['File', item.get('file', '')])
            detail_rows.append(['Confidence', item.get('confidence', 'Unknown')])
        dt = Table(detail_rows, colWidths=[3.2 * cm, 12.8 * cm])
        dt.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.3, C_GRAY),
            ('BACKGROUND', (0, 0), (0, -1), C_LIGHT),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(dt)
        story.append(Spacer(1, 0.35 * cm))


def _table_base() -> TableStyle:
    return TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), C_WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [C_WHITE, C_LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.3, C_GRAY),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ])


def _add_page_header(canvas, doc):
    canvas.saveState()
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(C_GRAY)
    canvas.drawString(2 * cm, A4[1] - 1.5 * cm, 'VulnScanX - Vulnerability Assessment Report')
    canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 1.5 * cm, datetime.utcnow().strftime('%Y-%m-%d'))
    canvas.drawCentredString(A4[0] / 2, 1 * cm, f'Page {doc.page}')
    canvas.restoreState()


def _build_recommendations(vulns, malware, ports, hdrs) -> list:
    recs = []
    names = {v.get('name', '') for v in vulns}
    malware_families = {m.get('family', '') for m in malware}

    if any('SQL' in n for n in names):
        recs.append('Use parameterised queries or prepared statements to prevent SQL injection.')
    if any('XSS' in n for n in names):
        recs.append('Sanitise and escape all user-controlled output and implement a strict Content-Security-Policy.')
    if any('Redirect' in n for n in names):
        recs.append('Validate or whitelist redirect destinations and never trust user-supplied URLs.')
    if any('Sensitive' in n for n in names):
        recs.append('Remove or restrict access to sensitive files such as .env, .git, and backups.')

    if 'Trojan' in malware_families:
        recs.append('Isolate the affected host, review persistence mechanisms, and block suspicious outbound command channels.')
    if 'Worm' in malware_families:
        recs.append('Segment the network and disable removable-media autorun and lateral-movement paths.')
    if 'Ransomware' in malware_families:
        recs.append('Restore from known-good backups, revoke exposed credentials, and investigate encryption activity immediately.')
    if 'Rootkit' in malware_families:
        recs.append('Rebuild the affected system from trusted media because kernel-level tampering cannot be trusted in place.')
    if 'Spyware' in malware_families or 'Keylogger' in malware_families:
        recs.append('Rotate credentials, review browser/session tokens, and check for unauthorized data exfiltration.')

    open_set = {p['port'] for p in ports if p.get('state') == 'open'}
    if 23 in open_set:
        recs.append('Disable Telnet (port 23) and use SSH instead.')
    if 21 in open_set:
        recs.append('Disable or secure FTP (port 21) and prefer SFTP or FTPS.')
    if 3389 in open_set:
        recs.append('Restrict RDP (port 3389) to VPN or allowlisted IPs.')
    if 6379 in open_set:
        recs.append('Require authentication on Redis (port 6379) and bind it to localhost when possible.')

    missing_hdrs = [h for h, v in hdrs.items() if v == 'MISSING']
    if missing_hdrs:
        recs.append(f"Add missing security headers: {', '.join(missing_hdrs)}.")

    if not recs:
        recs.append('No critical issues found. Perform regular security audits and keep software updated.')
    return recs


def _solution_for_finding(item, malware_mode=False) -> str:
    if malware_mode:
        family = item.get('family', '')
        detection_type = item.get('detection_type', '')
        if family == 'Trojan':
            return 'Quarantine the file, isolate the affected host, remove persistence entries, and review outbound command-and-control traffic.'
        if family == 'Worm':
            return 'Isolate the system from the network, disable lateral-movement paths, inspect shared folders, and scan neighboring hosts.'
        if family == 'Ransomware':
            return 'Disconnect the host immediately, preserve forensic evidence, restore from clean backups, and rotate exposed credentials.'
        if family == 'Rootkit':
            return 'Treat the host as untrusted, rebuild from known-good media, and verify firmware, drivers, and startup entries before reconnecting.'
        if family == 'Spyware':
            return 'Remove the sample, rotate user credentials and session tokens, and review browser, clipboard, camera, and microphone access.'
        if family == 'Keylogger':
            return 'Remove the file, rotate all typed credentials, reissue MFA secrets if needed, and inspect the host for keyboard hooks or hidden logs.'
        if detection_type == 'hash':
            return 'Block the exact hash across endpoint controls and search the environment for additional copies of the same sample.'
        return 'Quarantine the file, validate it with endpoint protection, and investigate the host for persistence and related artifacts.'

    name = item.get('name', '')
    if 'SQL Injection' in name:
        return 'Use parameterized queries, validate inputs server-side, and avoid building SQL statements with string concatenation.'
    if 'Cross-Site Scripting' in name or 'XSS' in name:
        return 'Encode untrusted output, sanitize rich content, and add a strict Content-Security-Policy.'
    if 'Open Redirect' in name:
        return 'Allow only trusted redirect destinations or use server-side route names instead of user-controlled URLs.'
    if 'Sensitive File Exposure' in name:
        return 'Remove exposed backup or config files from the web root and deny direct access at the web server level.'
    if 'Missing Header' in name:
        header = name.split(':', 1)[-1].strip()
        return f'Configure the application or reverse proxy to send the {header} header with a secure value.'
    if 'Connection Error' in name:
        return 'Verify the target URL, DNS resolution, routing, firewall rules, and whether the application is reachable from the scanner.'
    return 'Review the affected component, patch the vulnerable code path, and retest after remediation.'
