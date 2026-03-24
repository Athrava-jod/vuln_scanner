"""
scanner/cvss.py
────────────────
Simplified CVSS v3.1 base-score approximation.

Real CVSS v3.1 requires AV/AC/PR/UI/S/C/I/A vectors.
Since we can't fully determine these automatically from passive scanning,
we use a weighted heuristic that maps:
  • Vulnerability severity levels → CVSS sub-scores
  • Risky open ports              → additional score contribution

The formula is inspired by the CVSS v3.1 base score curve but is
intentionally simplified for an educational project.

Severity weights (per finding):
  Critical  → 9.5
  High      → 7.5
  Medium    → 5.0
  Low       → 2.0
  Info      → 0.5
"""

from typing import List, Dict

SEVERITY_WEIGHTS = {
    'Critical': 9.5,
    'High':     7.5,
    'Medium':   5.0,
    'Low':      2.0,
    'Info':     0.5,
}

# Risky ports that add to the base CVSS score
RISKY_PORT_SCORES = {
    23:   2.0,   # Telnet  – cleartext auth
    21:   1.5,   # FTP     – cleartext auth
    3389: 2.0,   # RDP     – common brute-force target
    5900: 1.5,   # VNC     – commonly misconfigured
    6379: 2.0,   # Redis   – often unauthenticated
    445:  1.5,   # SMB     – ransomware vector
    135:  1.0,   # MSRPC
    139:  1.0,   # NetBIOS
}


def calculate_cvss(vulnerabilities: List[Dict], open_ports: List[Dict]) -> float:
    """
    Returns a CVSS-like base score in [0, 10].

    Algorithm:
      1. Take the highest individual severity weight found.
      2. Add a dampened sum contribution from all other findings.
      3. Add a port-risk bonus for each open risky port.
      4. Clamp to [0, 10].
    """
    if not vulnerabilities and not open_ports:
        return 0.0

    # ── Vuln contribution ─────────────────────────────────────────────────────
    weights = sorted(
        [SEVERITY_WEIGHTS.get(v.get('severity', 'Info'), 0.5) for v in vulnerabilities],
        reverse=True
    )

    if weights:
        base = weights[0]                               # highest severity anchors score
        for w in weights[1:]:
            base += w * 0.15                            # each additional finding adds 15 %
    else:
        base = 0.0

    # ── Port risk contribution ────────────────────────────────────────────────
    port_bonus = 0.0
    open_port_nums = {p['port'] for p in open_ports if p.get('state') == 'open'}
    for port, bonus in RISKY_PORT_SCORES.items():
        if port in open_port_nums:
            port_bonus += bonus * 0.2                  # ports contribute at 20 % weight

    total = base + port_bonus
    return round(min(total, 10.0), 1)
