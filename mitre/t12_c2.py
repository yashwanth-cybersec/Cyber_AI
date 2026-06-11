# mitre/t12_c2.py - TA0011 Command and Control
import time
from collections import defaultdict
C2_PROCS = ["cobalt","beacon","meterpreter","empire","sliver","havoc",
            "cobaltstrike","brute ratel","ngrok","frp","chisel"]
TOR_RANGES = ["10.0.","185.220.","51.77.","79.137.","5.188."]

class C2Detector:
    TACTIC_ID   = "TA0011"
    TACTIC_NAME = "Command and Control"
    def __init__(self):
        self.ip_intervals  = defaultdict(list)
        self.last_scan     = 0

    def detect(self, events):
        findings = []
        now = time.time()
        # Process-based C2 detection
        if now - self.last_scan > 15:
            self.last_scan = now
            try:
                import psutil
                for proc in psutil.process_iter(["pid","name","cmdline"]):
                    try:
                        name = (proc.info["name"] or "").lower()
                        cmd  = " ".join(proc.info["cmdline"] or []).lower()
                        if any(c in name or c in cmd for c in C2_PROCS):
                            findings.append({"type":"mitre_detection","technique_id":"T1071",
                                "technique_name":"Application Layer Protocol C2","tactic":self.TACTIC_NAME,
                                "severity":"CRITICAL","ip":"local","username":"unknown",
                                "process":name,"detail":f"C2 framework process: {name}",
                                "source":"mitre_c2","timestamp":now})
                            break
                    except Exception:
                        pass
            except ImportError:
                pass
        # Beacon interval detection from network events
        for e in events:
            if e.get("type") == "port_connect":
                ip = e.get("ip","")
                if ip and ip not in ("local","unknown",""):
                    self.ip_intervals[ip].append(now)
                    self.ip_intervals[ip] = [t for t in self.ip_intervals[ip] if now-t < 300]
                    if len(self.ip_intervals[ip]) >= 6:
                        intervals = [self.ip_intervals[ip][i+1]-self.ip_intervals[ip][i]
                                     for i in range(len(self.ip_intervals[ip])-1)]
                        if intervals:
                            variance = max(intervals) - min(intervals)
                            if variance < 5:
                                findings.append({"type":"mitre_detection","technique_id":"T1071.001",
                                    "technique_name":"Web Protocols C2 Beaconing","tactic":self.TACTIC_NAME,
                                    "severity":"HIGH","ip":ip,"username":"unknown",
                                    "detail":f"Beacon pattern from {ip}: {len(self.ip_intervals[ip])} regular connections",
                                    "source":"mitre_c2","timestamp":now})
                                self.ip_intervals[ip].clear()
        return findings[:3]
