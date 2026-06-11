# mitre/t07_defense_evasion.py - TA0005 Defense Evasion
import time, platform
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

MASQUERADE_NAMES = {"svchost","lsass","csrss","winlogon","services","explorer"}

class DefenseEvasionDetector:
    TACTIC_ID   = "TA0005"
    TACTIC_NAME = "Defense Evasion"
    def __init__(self):
        self.last_scan     = 0
        self.defender_seen = True

    def detect(self, events):
        findings = []
        now = time.time()
        if now - self.last_scan < 20: return findings
        self.last_scan = now
        if not PSUTIL_OK: return findings
        system32 = "c:\\windows\\system32\\"
        for proc in psutil.process_iter(["pid","name","exe","username"]):
            try:
                name = (proc.info["name"] or "").lower().replace(".exe","")
                exe  = (proc.info["exe"] or "").lower()
                if name in MASQUERADE_NAMES and exe and system32 not in exe:
                    findings.append({"type":"mitre_detection","technique_id":"T1036",
                        "technique_name":"Masquerading","tactic":self.TACTIC_NAME,
                        "severity":"CRITICAL","ip":"local",
                        "username":proc.info.get("username","unknown"),
                        "process":name,"detail":f"{name} running from wrong path: {exe[:80]}",
                        "source":"mitre_defense_evasion","timestamp":now})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if len(findings) >= 2: break
        # Check for log clearing in events
        for e in events:
            if e.get("event_id") == 1102 or "log_cleared" in str(e.get("type","")):
                findings.append({"type":"mitre_detection","technique_id":"T1070.001",
                    "technique_name":"Clear Windows Event Logs","tactic":self.TACTIC_NAME,
                    "severity":"CRITICAL","ip":e.get("ip","local"),
                    "username":e.get("username","unknown"),
                    "detail":"Windows Event Log was cleared","source":"mitre_defense_evasion","timestamp":now})
                break
        return findings[:3]
