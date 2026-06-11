# mitre/t01_reconnaissance.py - TA0043 Reconnaissance (via Honeypot)
import time, socket, threading
from collections import defaultdict

HONEYPOT_PORTS = [2222, 8888, 9999, 4444, 21]
HONEYPOT_BANNERS = {
    2222: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
    8888: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n",
    9999: b"5.7.36-MySQL Community Server\r\n",
    4444: b"\x00\x00\x00\x01\x00",
    21:   b"220 FTP Server ready.\r\n",
}
_findings = []
_port_hits = defaultdict(list)

def _honeypot_handler(conn, addr, port, now):
    try:
        banner = HONEYPOT_BANNERS.get(port, b"Connected\r\n")
        conn.send(banner)
        conn.close()
    except Exception:
        pass
    ip = addr[0]
    _port_hits[ip].append(now)
    entry = {"type":"mitre_detection","technique_id":"T1595",
        "technique_name":"Active Scanning / Honeypot Hit","tactic":"Reconnaissance",
        "severity":"HIGH","ip":ip,"username":"attacker",
        "detail":f"Honeypot port {port} hit from {ip}","source":"honeypot","timestamp":now}
    _findings.append(entry)
    if len(_port_hits[ip]) >= 3:
        _findings.append({"type":"mitre_detection","technique_id":"T1595.001",
            "technique_name":"Scanning IP Blocks","tactic":"Reconnaissance",
            "severity":"CRITICAL","ip":ip,"username":"attacker",
            "detail":f"Port scan: {ip} hit {len(_port_hits[ip])} honeypot ports",
            "source":"honeypot","timestamp":now})

def start_honeypots():
    for port in HONEYPOT_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(5)
            s.settimeout(1)
            def _accept(srv=s, p=port):
                while True:
                    try:
                        conn, addr = srv.accept()
                        t = threading.Thread(target=_honeypot_handler,
                                             args=(conn, addr, p, time.time()), daemon=True)
                        t.start()
                    except socket.timeout:
                        pass
                    except Exception:
                        break
            threading.Thread(target=_accept, daemon=True).start()
        except Exception:
            pass

class ReconnaissanceDetector:
    TACTIC_ID   = "TA0043"
    TACTIC_NAME = "Reconnaissance"
    def __init__(self):
        start_honeypots()
    def detect(self, events):
        found = list(_findings[:5])
        _findings.clear()
        return found
