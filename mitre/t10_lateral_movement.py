# mitre/t10_lateral_movement.py - TA0008 Lateral Movement
import time
from collections import defaultdict

LATERAL_PORTS = {22:"SSH",3389:"RDP",445:"SMB",5985:"WinRM",5986:"WinRM-SSL",
                 135:"RPC",139:"NetBIOS"}
LATERAL_PROCS = ["psexec","paexec","wmiexec","smbexec","atexec","dcomexec","winrm"]

class LateralMovementDetector:
    TACTIC_ID   = "TA0008"
    TACTIC_NAME = "Lateral Movement"
    def __init__(self):
        self.user_hosts = defaultdict(set)  # user -> set of hosts/IPs

    def detect(self, events):
        findings = []
        now = time.time()
        # Track user connecting to multiple systems
        for e in events:
            if e.get("type") in ("login_success","port_connect"):
                user = e.get("username","unknown")
                ip   = e.get("ip","")
                port = e.get("port",0)
                if ip and ip not in ("local","unknown","") and port in LATERAL_PORTS:
                    self.user_hosts[user].add(ip)
                    if len(self.user_hosts[user]) >= 3:
                        findings.append({"type":"mitre_detection","technique_id":"T1021",
                            "technique_name":"Remote Services","tactic":self.TACTIC_NAME,
                            "severity":"HIGH","ip":ip,"username":user,
                            "detail":f"Lateral movement: {user} accessed {len(self.user_hosts[user])} systems via {LATERAL_PORTS.get(port,'port '+str(port))}",
                            "source":"mitre_lateral","timestamp":now})
                        self.user_hosts[user].clear()
                        break
        # Check for lateral movement tools
        try:
            import psutil
            for proc in psutil.process_iter(["pid","name","cmdline"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    if any(l in name for l in LATERAL_PROCS):
                        findings.append({"type":"mitre_detection","technique_id":"T1021.002",
                            "technique_name":"SMB/Windows Admin Shares","tactic":self.TACTIC_NAME,
                            "severity":"CRITICAL","ip":"local","username":"unknown",
                            "process":name,"detail":f"Lateral movement tool: {name}",
                            "source":"mitre_lateral","timestamp":now})
                        break
                except Exception:
                    pass
        except ImportError:
            pass
        return findings[:3]
