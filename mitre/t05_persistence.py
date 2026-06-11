# mitre/t05_persistence.py - TA0003 Persistence
import time, os, platform
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

WINREG_OK = False
if platform.system() == "Windows":
    try:
        import winreg
        WINREG_OK = True
    except ImportError:
        pass

class PersistenceDetector:
    TACTIC_ID   = "TA0003"
    TACTIC_NAME = "Persistence"
    def __init__(self):
        self.baseline_services = set()
        self.baseline_users    = set()
        self.last_scan         = 0
        self._build_baseline()

    def _build_baseline(self):
        if not PSUTIL_OK: return
        try:
            self.baseline_users = {u.name for u in psutil.users()}
        except Exception:
            pass
        if platform.system() == "Windows":
            try:
                import subprocess
                r = subprocess.run(["sc","query","type=","all"],capture_output=True,text=True,timeout=5)
                for line in r.stdout.splitlines():
                    if "SERVICE_NAME:" in line:
                        self.baseline_services.add(line.split(":")[-1].strip())
            except Exception:
                pass

    def detect(self, events):
        findings = []
        now = time.time()
        if now - self.last_scan < 30: return findings
        self.last_scan = now
        if not PSUTIL_OK: return findings
        # New users
        try:
            current_users = {u.name for u in psutil.users()}
            new_users = current_users - self.baseline_users
            for u in new_users:
                findings.append({"type":"mitre_detection","technique_id":"T1136",
                    "technique_name":"Create Account","tactic":self.TACTIC_NAME,
                    "severity":"HIGH","ip":"local","username":u,
                    "detail":f"New user account detected: {u}",
                    "source":"mitre_persistence","timestamp":now})
            self.baseline_users = current_users
        except Exception:
            pass
        # New services (Windows)
        if platform.system() == "Windows":
            try:
                import subprocess
                r = subprocess.run(["sc","query","type=","all"],capture_output=True,text=True,timeout=5)
                current_svc = set()
                for line in r.stdout.splitlines():
                    if "SERVICE_NAME:" in line:
                        current_svc.add(line.split(":")[-1].strip())
                new_svc = current_svc - self.baseline_services
                for svc in new_svc:
                    findings.append({"type":"mitre_detection","technique_id":"T1543",
                        "technique_name":"Create or Modify System Process","tactic":self.TACTIC_NAME,
                        "severity":"HIGH","ip":"local","username":"SYSTEM",
                        "detail":f"New service installed: {svc}",
                        "source":"mitre_persistence","timestamp":now})
                self.baseline_services = current_svc
            except Exception:
                pass
        return findings[:3]
