# mitre/t11_collection.py - TA0009 Collection
import time, os, platform
ARCHIVE_EXTS = [".zip",".7z",".rar",".tar",".gz",".bz2"]
SENSITIVE_NAMES = ["password","credential","secret","key","token","config","backup"]

class CollectionDetector:
    TACTIC_ID   = "TA0009"
    TACTIC_NAME = "Collection"
    def __init__(self):
        self.last_scan     = 0
        self.known_archives = set()

    def detect(self, events):
        findings = []
        now = time.time()
        if now - self.last_scan < 30: return findings
        self.last_scan = now
        check_dirs = []
        if platform.system() == "Windows":
            check_dirs = [os.environ.get("TEMP","C:\\Temp"),
                          os.path.join(os.environ.get("USERPROFILE","C:\\Users\\User"),"Downloads")]
        else:
            check_dirs = ["/tmp","/var/tmp",os.path.expanduser("~/Downloads")]
        for d in check_dirs:
            if not os.path.exists(d): continue
            try:
                for f in os.listdir(d)[:50]:
                    fp = os.path.join(d, f)
                    if any(f.lower().endswith(ext) for ext in ARCHIVE_EXTS):
                        if fp not in self.known_archives:
                            self.known_archives.add(fp)
                            try:
                                sz = os.path.getsize(fp)
                                if sz > 1024*1024:  # > 1MB
                                    findings.append({"type":"mitre_detection","technique_id":"T1560",
                                        "technique_name":"Archive Collected Data","tactic":self.TACTIC_NAME,
                                        "severity":"MEDIUM","ip":"local","username":"unknown",
                                        "detail":f"Large archive in temp: {f} ({sz//1024}KB)",
                                        "source":"mitre_collection","timestamp":now})
                            except Exception:
                                pass
                    if any(s in f.lower() for s in SENSITIVE_NAMES):
                        findings.append({"type":"mitre_detection","technique_id":"T1005",
                            "technique_name":"Data from Local System","tactic":self.TACTIC_NAME,
                            "severity":"MEDIUM","ip":"local","username":"unknown",
                            "detail":f"Sensitive file in temp/downloads: {f}",
                            "source":"mitre_collection","timestamp":now})
            except Exception:
                pass
        return findings[:3]
