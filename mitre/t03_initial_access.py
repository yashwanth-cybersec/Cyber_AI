# mitre/t03_initial_access.py - TA0001 Initial Access
import time, platform
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

OFFICE_APPS = ["winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe"]
SHELLS      = ["cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe"]

class InitialAccessDetector:
    TACTIC_ID   = "TA0001"
    TACTIC_NAME = "Initial Access"
    def __init__(self):
        self.last_scan = 0

    def detect(self, events):
        findings = []
        now = time.time()
        if now - self.last_scan < 15: return findings
        self.last_scan = now
        if not PSUTIL_OK: return findings
        try:
            procs = {p.pid: p.info for p in psutil.process_iter(["pid","name","ppid","username"])
                     if p.info["name"]}
            for pid, info in procs.items():
                child  = (info.get("name") or "").lower()
                ppid   = info.get("ppid")
                if ppid and ppid in procs:
                    parent = (procs[ppid].get("name") or "").lower()
                    if any(o in parent for o in OFFICE_APPS) and any(s in child for s in SHELLS):
                        findings.append({"type":"mitre_detection","technique_id":"T1566.001",
                            "technique_name":"Spearphishing Attachment","tactic":self.TACTIC_NAME,
                            "severity":"CRITICAL","ip":"local",
                            "username":info.get("username","unknown"),
                            "detail":f"Office macro: {parent} spawned {child}",
                            "source":"mitre_initial_access","timestamp":now})
        except Exception:
            pass
        # External IPs connecting to management ports
        mgmt_ports = {22,3389,5985,5986,23}
        for e in events:
            ip   = e.get("ip","")
            port = e.get("port",0)
            if ip and ip not in ("local","unknown","") and port in mgmt_ports:
                if not any(ip.startswith(r) for r in ["192.168.","10.","172."]):
                    findings.append({"type":"mitre_detection","technique_id":"T1133",
                        "technique_name":"External Remote Services","tactic":self.TACTIC_NAME,
                        "severity":"HIGH","ip":ip,"username":"unknown",
                        "detail":f"External IP {ip} connecting to port {port}",
                        "source":"mitre_initial_access","timestamp":now})
        return findings[:3]
