# mitre/t13_exfiltration.py - TA0010 Exfiltration
import time
EXFIL_PROCS = ["rclone","mega","megacmd","gdrive","aws s3","curl -T","wget --post",
               "scp -r","rsync -av","ftp","sftp"]

class ExfiltrationDetector:
    TACTIC_ID   = "TA0010"
    TACTIC_NAME = "Exfiltration"
    def __init__(self):
        self.last_bytes = 0
        self.last_check = 0
        self.last_scan  = 0

    def detect(self, events):
        findings = []
        now = time.time()
        if now - self.last_scan < 20: return findings
        self.last_scan = now
        try:
            import psutil
            # Check for exfil tools
            for proc in psutil.process_iter(["pid","name","cmdline"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    cmd  = " ".join(proc.info["cmdline"] or []).lower()
                    if any(e in name or e in cmd for e in EXFIL_PROCS):
                        findings.append({"type":"mitre_detection","technique_id":"T1041",
                            "technique_name":"Exfiltration Over C2 Channel","tactic":self.TACTIC_NAME,
                            "severity":"HIGH","ip":"local","username":"unknown",
                            "detail":f"Exfiltration tool detected: {name}",
                            "source":"mitre_exfil","timestamp":now})
                        break
                except Exception:
                    pass
            # Check network bytes
            stats = psutil.net_io_counters()
            if self.last_bytes > 0:
                sent = stats.bytes_sent - self.last_bytes
                if sent > 50 * 1024 * 1024:  # 50MB spike
                    findings.append({"type":"mitre_detection","technique_id":"T1048",
                        "technique_name":"Exfiltration Over Alternative Protocol","tactic":self.TACTIC_NAME,
                        "severity":"HIGH","ip":"unknown","username":"unknown",
                        "detail":f"Large outbound transfer: {sent//1024//1024}MB",
                        "source":"mitre_exfil","timestamp":now})
            self.last_bytes = stats.bytes_sent
        except (ImportError, Exception):
            pass
        return findings[:3]
