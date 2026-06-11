# mitre/t08_credential_access.py - TA0006 Credential Access
import time
from collections import defaultdict

CRED_DUMP_PROCS = ["mimikatz","wce","pwdump","fgdump","lazagne","rubeus",
                   "crackmapexec","impacket","secretsdump"]

class CredentialAccessDetector:
    TACTIC_ID   = "TA0006"
    TACTIC_NAME = "Credential Access"
    def __init__(self):
        self.fail_tracker  = defaultdict(list)  # ip -> [timestamps]
        self.user_tracker  = defaultdict(set)   # ip -> set of usernames

    def detect(self, events):
        findings = []
        now = time.time()
        try:
            import psutil
            for proc in psutil.process_iter(["pid","name","exe"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    if any(c in name for c in CRED_DUMP_PROCS):
                        findings.append({"type":"mitre_detection","technique_id":"T1003",
                            "technique_name":"OS Credential Dumping","tactic":self.TACTIC_NAME,
                            "severity":"CRITICAL","ip":"local","username":"unknown",
                            "process":name,"detail":f"Credential dumper detected: {name}",
                            "source":"mitre_cred_access","timestamp":now})
                        break
                except Exception:
                    pass
        except ImportError:
            pass
        # Brute force detection from events
        for e in events:
            if e.get("type") == "fail_login":
                ip = e.get("ip","unknown")
                user = e.get("username","unknown")
                self.fail_tracker[ip].append(now)
                self.user_tracker[ip].add(user)
                # Clean old
                self.fail_tracker[ip] = [t for t in self.fail_tracker[ip] if now - t < 60]
                if len(self.fail_tracker[ip]) >= 5:
                    findings.append({"type":"mitre_detection","technique_id":"T1110",
                        "technique_name":"Brute Force","tactic":self.TACTIC_NAME,
                        "severity":"HIGH","ip":ip,"username":user,
                        "detail":f"Brute force: {len(self.fail_tracker[ip])} attempts in 60s from {ip}",
                        "source":"mitre_cred_access","timestamp":now})
                # Password spray: same IP, many users
                if len(self.user_tracker[ip]) >= 4:
                    findings.append({"type":"mitre_detection","technique_id":"T1110.003",
                        "technique_name":"Password Spraying","tactic":self.TACTIC_NAME,
                        "severity":"HIGH","ip":ip,"username":"multiple",
                        "detail":f"Password spray from {ip}: {len(self.user_tracker[ip])} users targeted",
                        "source":"mitre_cred_access","timestamp":now})
                    self.user_tracker[ip].clear()
        return findings[:4]
