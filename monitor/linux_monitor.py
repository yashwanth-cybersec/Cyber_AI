# monitor/linux_monitor.py
import platform, re, os, time
from collections import defaultdict

PATTERNS = [
    (re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)"), "fail_login",   "MEDIUM"),
    (re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"),                  "login_success","INFO"),
    (re.compile(r"sudo:\s+(\S+)\s+:.*?COMMAND=(.*)"),                                         "admin_access", "HIGH"),
    (re.compile(r"Invalid user (\S+) from ([\d.]+)"),                                          "fail_login",   "MEDIUM"),
]
LOG_FILES = ["/var/log/auth.log","/var/log/secure","/var/log/syslog"]

class LinuxMonitor:
    def __init__(self):
        self.positions = {}
        self.event_counts = defaultdict(int)
        self.logs = [f for f in LOG_FILES if os.path.exists(f)]
        for f in self.logs: self.positions[f] = 0

    def collect(self):
        if platform.system() != "Linux": return []
        ev = []
        for path in self.logs:
            try:
                with open(path,"r",errors="ignore") as f:
                    f.seek(self.positions.get(path,0))
                    for line in f.readlines():
                        parsed = self._parse(line.strip())
                        if parsed: ev.append(parsed)
                    self.positions[path] = f.tell()
            except Exception: pass
        return ev

    def _parse(self, line):
        for pat, etype, sev in PATTERNS:
            m = pat.search(line)
            if m:
                u = m.group(1) if m.lastindex >= 1 else "unknown"
                ip= m.group(2) if m.lastindex >= 2 else "local"
                self.event_counts[etype] += 1
                return {"type":etype,"ip":ip,"username":u.strip(),
                        "timestamp":time.time(),"source":"linux_syslog",
                        "severity":sev,"raw":line[:150]}
        return None
