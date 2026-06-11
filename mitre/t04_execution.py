# mitre/t04_execution.py - TA0002 Execution
import time, re
try:
    import psutil, winreg
    FULL_OK = True
except ImportError:
    try:
        import psutil
        FULL_OK = True
    except ImportError:
        FULL_OK = False

SUSPICIOUS_EXEC = ["powershell","cmd","wscript","cscript","mshta","regsvr32",
                   "rundll32","certutil","bitsadmin","msiexec"]
ENC_PATTERN = re.compile(r'-[Ee][Nn][Cc]|-[Ee][Nn][Cc][Oo][Dd][Ee][Dd]')

class ExecutionDetector:
    TACTIC_ID   = "TA0002"
    TACTIC_NAME = "Execution"
    def __init__(self):
        self.last_scan = 0
    def detect(self, events):
        findings = []
        now = time.time()
        if not FULL_OK or now - self.last_scan < 10:
            return findings
        self.last_scan = now
        try:
            for p in psutil.process_iter(["pid","name","cmdline","ppid"]):
                try:
                    name = (p.info["name"] or "").lower()
                    cmd  = " ".join(p.info["cmdline"] or [])
                    if any(s in name for s in SUSPICIOUS_EXEC):
                        severity = "HIGH"
                        tid = "T1059"
                        if ENC_PATTERN.search(cmd):
                            severity = "CRITICAL"
                            tid = "T1059.001"
                        if "iex" in cmd.lower() or "invoke-expression" in cmd.lower():
                            severity = "CRITICAL"
                            tid = "T1059.001"
                        findings.append({"type":"mitre_detection","technique_id":tid,
                            "technique_name":"Command and Scripting Interpreter",
                            "tactic":self.TACTIC_NAME,"severity":severity,
                            "ip":"local","username":"unknown","process":name,
                            "detail":cmd[:200],"source":"mitre_execution",
                            "timestamp":now})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        return findings[:5]
