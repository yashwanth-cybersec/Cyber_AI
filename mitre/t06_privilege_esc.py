# mitre/t06_privilege_esc.py - TA0004 Privilege Escalation
import time, platform
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

DANGEROUS_PRIVS = ["SeDebugPrivilege","SeImpersonatePrivilege","SeTakeOwnershipPrivilege",
                   "SeLoadDriverPrivilege","SeRestorePrivilege"]
UAC_BYPASS = ["fodhelper.exe","eventvwr.exe","sdclt.exe","slui.exe","computerdefaults.exe"]

class PrivEscDetector:
    TACTIC_ID   = "TA0004"
    TACTIC_NAME = "Privilege Escalation"
    def __init__(self):
        self.last_scan = 0

    def detect(self, events):
        findings = []
        now = time.time()
        if now - self.last_scan < 15: return findings
        self.last_scan = now
        if not PSUTIL_OK: return findings
        # Check for processes running as SYSTEM unexpectedly
        for proc in psutil.process_iter(["pid","name","username","cmdline"]):
            try:
                name  = (proc.info["name"] or "").lower()
                user  = (proc.info["username"] or "").lower()
                cmd   = " ".join(proc.info["cmdline"] or []).lower()
                if any(uac in name for uac in UAC_BYPASS):
                    findings.append({"type":"mitre_detection","technique_id":"T1548.002",
                        "technique_name":"Bypass User Account Control","tactic":self.TACTIC_NAME,
                        "severity":"CRITICAL","ip":"local","username":proc.info.get("username","unknown"),
                        "process":name,"detail":f"UAC bypass process: {name}",
                        "source":"mitre_priv_esc","timestamp":now})
                if "system" in user and any(s in name for s in ["cmd","powershell","wscript"]):
                    findings.append({"type":"mitre_detection","technique_id":"T1134",
                        "technique_name":"Access Token Manipulation","tactic":self.TACTIC_NAME,
                        "severity":"HIGH","ip":"local","username":"SYSTEM","process":name,
                        "detail":f"SYSTEM running shell: {name}",
                        "source":"mitre_priv_esc","timestamp":now})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if len(findings) >= 3: break
        # Check events for admin_access
        for e in events:
            if e.get("type") == "admin_access":
                findings.append({"type":"mitre_detection","technique_id":"T1548",
                    "technique_name":"Privilege Escalation Detected","tactic":self.TACTIC_NAME,
                    "severity":"HIGH","ip":e.get("ip","local"),"username":e.get("username","unknown"),
                    "detail":"Admin access event detected","source":"mitre_priv_esc","timestamp":now})
                break
        return findings[:3]
