# mitre/t14_impact.py - TA0040 Impact
import time, platform
RANSOMWARE_CMDS = ["vssadmin delete shadows","bcdedit /set","wbadmin delete",
                   "cipher /w","taskkill /f /im sql","net stop vss"]
RANSOMWARE_EXTS = [".locked",".encrypted",".crypto",".crypt",".enc",".ransomed",
                   ".pay2decrypt",".crypted",".locky",".wcry",".wncry"]

class ImpactDetector:
    TACTIC_ID   = "TA0040"
    TACTIC_NAME = "Impact"
    def __init__(self):
        self.last_scan = 0
        self.high_cpu_count = 0

    def detect(self, events):
        findings = []
        now = time.time()
        if now - self.last_scan < 15: return findings
        self.last_scan = now
        try:
            import psutil
            # Ransomware process detection
            for proc in psutil.process_iter(["pid","name","cmdline","username"]):
                try:
                    cmd  = " ".join(proc.info["cmdline"] or []).lower()
                    name = (proc.info["name"] or "").lower()
                    if any(r in cmd for r in RANSOMWARE_CMDS):
                        findings.append({"type":"mitre_detection","technique_id":"T1490",
                            "technique_name":"Inhibit System Recovery","tactic":self.TACTIC_NAME,
                            "severity":"CRITICAL","ip":"local",
                            "username":proc.info.get("username","SYSTEM"),
                            "detail":f"Ransomware command: {cmd[:100]}",
                            "source":"mitre_impact","timestamp":now})
                        break
                    if "encrypt" in name or "locker" in name:
                        findings.append({"type":"mitre_detection","technique_id":"T1486",
                            "technique_name":"Data Encrypted for Impact","tactic":self.TACTIC_NAME,
                            "severity":"CRITICAL","ip":"local","username":"SYSTEM",
                            "detail":f"Ransomware process: {name}",
                            "source":"mitre_impact","timestamp":now})
                        break
                except Exception:
                    pass
            # CPU spike = possible cryptominer/ransomware
            cpu = psutil.cpu_percent(interval=0.1)
            if cpu > 85:
                self.high_cpu_count += 1
                if self.high_cpu_count >= 3:
                    findings.append({"type":"mitre_detection","technique_id":"T1496",
                        "technique_name":"Resource Hijacking","tactic":self.TACTIC_NAME,
                        "severity":"MEDIUM","ip":"local","username":"unknown",
                        "detail":f"Sustained high CPU: {cpu}% (possible cryptominer/ransomware)",
                        "source":"mitre_impact","timestamp":now})
                    self.high_cpu_count = 0
            else:
                self.high_cpu_count = max(0, self.high_cpu_count - 1)
        except (ImportError, Exception):
            pass
        return findings[:3]
