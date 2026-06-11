# mitre/t09_discovery.py - TA0007 Discovery
import time
from collections import deque

RECON_CMDS = ["whoami","net user","net group","systeminfo","ipconfig","hostname",
              "tasklist","netstat","nmap","ping","arp","route","sc query","reg query",
              "wmic","bloodhound","sharphound","adrecon"]

class DiscoveryDetector:
    TACTIC_ID   = "TA0007"
    TACTIC_NAME = "Discovery"
    def __init__(self):
        self.recon_times = deque(maxlen=50)

    def detect(self, events):
        findings = []
        now = time.time()
        try:
            import psutil
            for proc in psutil.process_iter(["pid","name","cmdline","username"]):
                try:
                    cmd = " ".join(proc.info["cmdline"] or []).lower()
                    if any(r in cmd for r in RECON_CMDS):
                        self.recon_times.append(now)
                        # Burst: 6+ recon commands in 2 minutes
                        recent = [t for t in self.recon_times if now - t < 120]
                        if len(recent) >= 4:
                            findings.append({"type":"mitre_detection","technique_id":"T1082",
                                "technique_name":"System Information Discovery","tactic":self.TACTIC_NAME,
                                "severity":"MEDIUM","ip":"local",
                                "username":proc.info.get("username","unknown"),
                                "detail":f"Recon burst: {len(recent)} commands in 2 min",
                                "source":"mitre_discovery","timestamp":now})
                            self.recon_times.clear()
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except ImportError:
            pass
        # Port scan detection from network events
        ips = [e.get("ip") for e in events if e.get("type")=="port_connect" and e.get("ip") not in ("","local","unknown")]
        if len(set(ips)) >= 3:
            findings.append({"type":"mitre_detection","technique_id":"T1046",
                "technique_name":"Network Service Discovery","tactic":self.TACTIC_NAME,
                "severity":"MEDIUM","ip":ips[0],"username":"unknown",
                "detail":f"Port scan from {len(set(ips))} IPs detected",
                "source":"mitre_discovery","timestamp":now})
        return findings[:3]
