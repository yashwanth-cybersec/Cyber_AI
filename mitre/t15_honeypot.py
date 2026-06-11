# mitre/t15_honeypot.py  — TA0043 Reconnaissance via Honeypot

import time
import socket
import threading
from collections import defaultdict

_honeypot_hits  = []          # list of hit records
_port_hit_map   = defaultdict(list)   # ip -> [ports]
_listener_threads = []
_running = False

HONEYPOT_PORTS = {
    2222 : "Fake SSH",
    8888 : "Fake Admin Panel",
    9999 : "Fake Database",
    4444 : "Metasploit Canary",
    21   : "Fake FTP",
}

BANNERS = {
    2222 : b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    8888 : b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><h1>Admin Panel</h1></html>",
    9999 : b"+OK CyberAI-DB ready\r\n",
    4444 : b"[*] Meterpreter session 1 opened\r\n",
    21   : b"220 CyberAI FTP Server ready\r\n",
}


def _handle_conn(conn, addr, port):
    global _honeypot_hits
    try:
        banner = BANNERS.get(port, b"Connection accepted\r\n")
        conn.send(banner)
        conn.settimeout(2)
        try:
            data = conn.recv(256)
        except Exception:
            data = b""
        conn.close()
    except Exception:
        pass

    ip  = addr[0]
    now = time.time()
    hit = {
        "ip"            : ip,
        "port"          : port,
        "service"       : HONEYPOT_PORTS.get(port, f"Port {port}"),
        "timestamp"     : now,
        "data_received" : len(data) if 'data' in dir() else 0,
    }
    _honeypot_hits.append(hit)
    _port_hit_map[ip].append(port)


def _start_listener(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        s.settimeout(2)
        while _running:
            try:
                conn, addr = s.accept()
                t = threading.Thread(target=_handle_conn, args=(conn, addr, port), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break
        s.close()
    except Exception:
        pass


def start_honeypot():
    global _running, _listener_threads
    _running = True
    started  = []
    for port in HONEYPOT_PORTS:
        t = threading.Thread(target=_start_listener, args=(port,), daemon=True)
        t.start()
        _listener_threads.append(t)
        started.append(port)
    if started:
        print(f"  [Honeypot] Started on ports: {started}")
    return started


class HoneypotDetector:

    def __init__(self):
        self._started = False
        self._seen    = set()

    def _ensure_started(self):
        if not self._started:
            start_honeypot()
            self._started = True

    def detect(self, events):
        self._ensure_started()
        findings = []
        now      = time.time()
        cutoff   = now - 30   # hits in last 30 seconds

        new_hits = [h for h in _honeypot_hits
                    if h["timestamp"] > cutoff and
                    (h["ip"], h["port"]) not in self._seen]

        for hit in new_hits:
            self._seen.add((hit["ip"], hit["port"]))
            findings.append({
                "type"          : "mitre_detection",
                "technique_id"  : "T1595",
                "technique_name": "Active Scanning / Honeypot",
                "ip"            : hit["ip"],
                "username"      : "unknown",
                "severity"      : "CRITICAL",
                "detail"        : f"Honeypot hit: {hit['service']} port {hit['port']}",
                "timestamp"     : now,
                "source"        : "mitre_t15_honeypot"
            })

        # Detect port scan pattern (same IP hitting 3+ honeypot ports)
        for ip, ports in _port_hit_map.items():
            if len(set(ports)) >= 3:
                findings.append({
                    "type"          : "mitre_detection",
                    "technique_id"  : "T1046",
                    "technique_name": "Network Port Scan via Honeypot",
                    "ip"            : ip,
                    "username"      : "unknown",
                    "severity"      : "CRITICAL",
                    "detail"        : f"Port scan detected: {ip} hit {len(set(ports))} honeypot ports",
                    "timestamp"     : now,
                    "source"        : "mitre_t15_honeypot"
                })

        return findings
