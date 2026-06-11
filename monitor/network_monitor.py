# monitor/network_monitor.py
import time
from collections import defaultdict
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

HIGH_RISK_PORTS = {4444:"Metasploit",1337:"Backdoor",31337:"Back Orifice",
                   6666:"IRC/C2",9001:"Tor",9050:"Tor Proxy",8888:"Reverse Shell"}
IGNORE_IPS = {"127.0.0.1","::1","0.0.0.0","::",""}
PRIVATE_RANGES = ["192.168.","10.","172.16.","172.17.","172.18.","172.19."]

class NetworkMonitor:
    def __init__(self):
        self.known_connections = set()
        self.known_listeners   = set()
        self.event_counts      = defaultdict(int)
        self._snapshot()

    def _snapshot(self):
        if not PSUTIL_OK: return
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "ESTABLISHED" and c.raddr:
                    self.known_connections.add((c.laddr.port, c.raddr.ip, c.raddr.port))
                elif c.status == "LISTEN":
                    self.known_listeners.add(c.laddr.port)
        except Exception:
            pass

    def collect(self):
        if not PSUTIL_OK: return []
        events = []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return []
        current_conns, current_listen = set(), set()
        for c in conns:
            try:
                if c.status == "ESTABLISHED" and c.raddr:
                    key = (c.laddr.port, c.raddr.ip, c.raddr.port)
                    current_conns.add(key)
                    if c.raddr.port in HIGH_RISK_PORTS:
                        events.append({"type":"port_connect","ip":c.raddr.ip,"username":"unknown",
                            "port":c.raddr.port,"source":"network_monitor","severity":"CRITICAL",
                            "detail":f"HIGH RISK PORT {c.raddr.port}: {HIGH_RISK_PORTS[c.raddr.port]}",
                            "timestamp":time.time()})
                elif c.status == "LISTEN":
                    current_listen.add(c.laddr.port)
                    if c.laddr.port not in self.known_listeners:
                        sev = "CRITICAL" if c.laddr.port in HIGH_RISK_PORTS else "MEDIUM"
                        events.append({"type":"port_connect","ip":"local","username":"unknown",
                            "port":c.laddr.port,"source":"network_monitor","severity":sev,
                            "detail":f"New service listening on port {c.laddr.port}","timestamp":time.time()})
            except Exception:
                pass
        new_conns = current_conns - self.known_connections
        for lp, rip, rp in new_conns:
            if rip not in IGNORE_IPS:
                is_pub = not any(rip.startswith(r) for r in PRIVATE_RANGES)
                events.append({"type":"port_connect","ip":rip,"username":"unknown",
                    "port":rp,"source":"network_monitor","severity":"MEDIUM" if is_pub else "LOW",
                    "timestamp":time.time(),"detail":f"New connection {rip}:{rp}"})
        self.known_connections = current_conns
        self.known_listeners   = current_listen
        return events
