# advanced/polymorphic_detector.py  — Polymorphic Malware Detection

import time
import os

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

WRONG_LOCATIONS = {
    "svchost.exe" : ["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"],
    "lsass.exe"   : ["c:\\windows\\system32\\"],
    "csrss.exe"   : ["c:\\windows\\system32\\"],
    "winlogon.exe": ["c:\\windows\\system32\\"],
    "explorer.exe": ["c:\\windows\\"],
    "taskhost.exe": ["c:\\windows\\system32\\"],
}

INJECTION_APIS = [
    "virtualalloc", "writeprocessmemory", "createremotethread",
    "ntcreatethreaded", "rtlcreateuserthread"
]

HOLLOW_INDICATORS = [
    "\\temp\\svchost", "\\temp\\lsass", "\\appdata\\roaming\\svchost",
    "\\users\\public\\svchost", "%temp%\\", "\\programdata\\"
]


class PolymorphicDetector:

    def __init__(self):
        self._known_hashes = {}   # pid -> exe path (for change detection)
        self._alerts_sent  = set()

    def detect(self, events):
        findings = []
        now      = time.time()

        if not PSUTIL_OK:
            return []

        try:
            for proc in psutil.process_iter(["pid","name","exe","cmdline","username"]):
                try:
                    pid  = proc.info["pid"]
                    name = (proc.info["name"] or "").lower()
                    exe  = (proc.info["exe"]  or "").lower()
                    cmd  = " ".join(proc.info["cmdline"] or []).lower()

                    # Check for system process in wrong location
                    if name in WRONG_LOCATIONS:
                        allowed = WRONG_LOCATIONS[name]
                        if exe and not any(exe.startswith(loc) for loc in allowed):
                            key = f"loc_{pid}"
                            if key not in self._alerts_sent:
                                self._alerts_sent.add(key)
                                findings.append({
                                    "type"          : "mitre_detection",
                                    "technique_id"  : "T1055",
                                    "technique_name": "Process Masquerading / Hollowing",
                                    "ip"            : "local",
                                    "username"      : proc.info.get("username") or "unknown",
                                    "severity"      : "CRITICAL",
                                    "detail"        : f"{name} running from wrong location: {exe}",
                                    "pid"           : pid,
                                    "timestamp"     : now,
                                    "source"        : "polymorphic_detector"
                                })

                    # Check hollow indicators in path
                    if exe and any(ind in exe for ind in HOLLOW_INDICATORS):
                        key = f"hollow_{pid}"
                        if key not in self._alerts_sent:
                            self._alerts_sent.add(key)
                            findings.append({
                                "type"          : "mitre_detection",
                                "technique_id"  : "T1055.012",
                                "technique_name": "Process Hollowing",
                                "ip"            : "local",
                                "username"      : proc.info.get("username") or "unknown",
                                "severity"      : "CRITICAL",
                                "detail"        : f"Executable in suspicious location: {exe[:80]}",
                                "pid"           : pid,
                                "timestamp"     : now,
                                "source"        : "polymorphic_detector"
                            })

                    # PowerShell with encoded command (polymorphic dropper)
                    if "powershell" in name and "-enc" in cmd:
                        key = f"ps_enc_{pid}"
                        if key not in self._alerts_sent:
                            self._alerts_sent.add(key)
                            findings.append({
                                "type"          : "mitre_detection",
                                "technique_id"  : "T1027",
                                "technique_name": "Obfuscated / Encoded Payload",
                                "ip"            : "local",
                                "username"      : proc.info.get("username") or "unknown",
                                "severity"      : "HIGH",
                                "detail"        : "PowerShell encoded command — possible dropper",
                                "pid"           : pid,
                                "timestamp"     : now,
                                "source"        : "polymorphic_detector"
                            })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except Exception:
            pass

        # Clean up old alert keys to prevent memory growth
        if len(self._alerts_sent) > 500:
            self._alerts_sent = set(list(self._alerts_sent)[-250:])

        return findings
