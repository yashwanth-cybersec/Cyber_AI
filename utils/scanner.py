# utils/scanner.py
import socket
PORTS = {
    22:   ("SSH",       "HIGH",     "SSH allows remote login - disable if unused"),
    23:   ("Telnet",    "CRITICAL", "Telnet is unencrypted - disable immediately"),
    80:   ("HTTP",      "MEDIUM",   "Web server running - ensure properly secured"),
    443:  ("HTTPS",     "LOW",      "HTTPS server - verify certificate"),
    3306: ("MySQL",     "HIGH",     "Database exposed - restrict to localhost"),
    5432: ("PostgreSQL","HIGH",     "Database exposed - restrict to localhost"),
    6379: ("Redis",     "CRITICAL", "Redis exposed - has no auth by default"),
    8080: ("HTTP-Alt",  "MEDIUM",   "Alt web server - check configuration"),
    3389: ("RDP",       "HIGH",     "Remote Desktop - disable if unused"),
}
def scan_local_ports():
    found = []
    for port,(svc,sev,advice) in PORTS.items():
        try:
            with socket.socket() as s:
                s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    found.append({"port":port,"service":svc,"severity":sev,"advice":advice})
        except Exception: pass
    return found
def get_vulnerabilities():
    return [f"{f['service']} port open (:{f['port']})" for f in scan_local_ports()]
