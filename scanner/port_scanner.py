"""
scanner/port_scanner.py
────────────────────────
Advanced port scanner using python-nmap.
Falls back to socket-based scanning if nmap binary is unavailable
(common on shared/serverless hosts).

How it works:
  1. python-nmap calls the system `nmap` binary with service detection (-sV)
  2. Results are parsed and returned as a list of port-info dicts
  3. If nmap is not installed, concurrent.futures.ThreadPoolExecutor
     is used to connect to each port with Python sockets – much faster
     than sequential scanning.
"""

import socket
import concurrent.futures
from typing import Callable, List, Dict

# ── Ports to check ─────────────────────────────────────────────────────────────
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888]

# ── Well-known service names (fallback when nmap not available) ────────────────
PORT_SERVICES = {
    21:   'FTP',
    22:   'SSH',
    23:   'Telnet',
    25:   'SMTP',
    53:   'DNS',
    80:   'HTTP',
    110:  'POP3',
    135:  'MSRPC',
    139:  'NetBIOS',
    143:  'IMAP',
    443:  'HTTPS',
    445:  'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    8888: 'HTTP-Dev',
}

# Ports that are considered risky when open (used by risk/CVSS logic)
RISKY_PORTS = {21, 23, 3389, 5900, 6379}


def run_port_scan(target: str, progress_cb: Callable = None) -> List[Dict]:
    """
    Entry point called by app.py.
    Returns list of dicts:
      { port, state, service, version, risk }
    """
    host = _normalize_host(target)

    try:
        import nmap  # python-nmap
        return _nmap_scan(host, progress_cb)
    except ImportError:
        return _socket_scan(host, progress_cb)


# ──────────────────────────────────────────────────────────────────────────────
# nmap-based scan
# ──────────────────────────────────────────────────────────────────────────────

def _nmap_scan(host: str, progress_cb: Callable) -> List[Dict]:
    """
    Uses python-nmap to run:  nmap -sV -T4 -p <ports> <host>
    -sV   : service/version detection
    -T4   : aggressive timing (faster)
    """
    import nmap

    nm        = nmap.PortScanner()
    port_list = ','.join(map(str, COMMON_PORTS))

    if progress_cb:
        progress_cb(0.1)

    # Scan: version detection, no ping (-Pn for hosts that block ICMP)
    nm.scan(hosts=host, ports=port_list, arguments='-sV -T4 -Pn')

    if progress_cb:
        progress_cb(0.8)

    results = []
    for host_key in nm.all_hosts():
        tcp = nm[host_key].get('tcp', {})
        for port, info in tcp.items():
            results.append({
                'port':    port,
                'state':   info.get('state', 'unknown'),
                'service': info.get('name', PORT_SERVICES.get(port, 'unknown')),
                'version': f"{info.get('product','')} {info.get('version','')}".strip(),
                'risk':    'High' if port in RISKY_PORTS else 'Medium' if info.get('state') == 'open' else 'Low',
            })

    if progress_cb:
        progress_cb(1.0)

    return results


# ──────────────────────────────────────────────────────────────────────────────
# Socket-based fallback (multi-threaded)
# ──────────────────────────────────────────────────────────────────────────────

def _socket_scan(host: str, progress_cb: Callable) -> List[Dict]:
    """
    Thread-pool socket scanner – checks all COMMON_PORTS in parallel.
    Much faster than sequential scanning (all ports checked ~simultaneously).
    """
    results     = []
    total       = len(COMMON_PORTS)
    completed   = 0

    def check_port(port: int) -> Dict:
        """Try to connect; timeout after 1 s"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            state = 'open' if result == 0 else 'closed'
        except Exception:
            state = 'filtered'

        return {
            'port':    port,
            'state':   state,
            'service': PORT_SERVICES.get(port, 'unknown'),
            'version': '',
            'risk':    'High' if (state == 'open' and port in RISKY_PORTS)
                       else 'Medium' if state == 'open'
                       else 'Low',
        }

    # Use up to 50 worker threads – reduces wall-clock time dramatically
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_port, p): p for p in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            if progress_cb:
                progress_cb(completed / total)
            results.append(future.result())

    # Sort open ports first, then by port number
    results.sort(key=lambda x: (0 if x['state'] == 'open' else 1, x['port']))
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────────────────────

def _normalize_host(target: str) -> str:
    """Strip protocol/path, return bare hostname or IP"""
    target = target.strip()
    for prefix in ('https://', 'http://'):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split('/')[0].split(':')[0]
