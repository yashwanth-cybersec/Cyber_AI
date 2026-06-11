# mitre/t02_resource_dev.py - TA0042 Resource Development (via Threat Intel)
import time
from collections import defaultdict
KNOWN_BAD_RANGES = [
    "185.220.","51.77.","79.137.","5.188.206.","194.165.16.",
    "45.33.32.","91.108.4.","91.108.56.","149.154.",
]
_flagged = {}

class ResourceDevDetector:
    TACTIC_ID   = "TA0042"
    TACTIC_NAME = "Resource Development"
    def __init__(self):
        self.checked = defaultdict(float)

    def detect(self, events):
        findings = []
        now = time.time()
        for e in events:
            ip = e.get("ip","")
            if not ip or ip in ("local","unknown","127.0.0.1",""):
                continue
            if now - self.checked.get(ip,0) < 300:
                continue
            self.checked[ip] = now
            if any(ip.startswith(r) for r in KNOWN_BAD_RANGES):
                findings.append({"type":"mitre_detection","technique_id":"T1583",
                    "technique_name":"Known Malicious Infrastructure","tactic":self.TACTIC_NAME,
                    "severity":"HIGH","ip":ip,"username":"unknown",
                    "detail":f"IP {ip} matches known attacker infrastructure range",
                    "source":"threat_intel","timestamp":now})
        return findings[:3]
