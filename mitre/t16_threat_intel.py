# mitre/t16_threat_intel.py  — TA0042 Resource Development (Threat Intel)

import time
import os
import json
import threading

try:
    import urllib.request
    HTTP_OK = True
except ImportError:
    HTTP_OK = False

INTEL_FILE = "memory_threat_intel.json"

# Known bad CIDR ranges (Tor exit nodes, scanners, C2 infra)
BAD_RANGES = [
    "185.220.",  # Tor exit nodes
    "45.33.",    # Linode abuse
    "194.165.",  # Known C2
    "91.108.",   # Telegram/abuse
    "5.188.",    # Bulletproof hosting
    "185.234.",  # Malware C2
    "23.129.",   # Tor exit
    "199.87.",   # VPN/TOR
]

# IPs with confirmed abuse (static list for offline use)
KNOWN_BAD_IPS = {
    "45.33.32.156", "185.220.101.45", "91.108.4.180",
    "194.165.16.77", "5.188.206.14",
}

_blacklist   = set(KNOWN_BAD_IPS)
_cache       = {}   # ip -> {score, checked_at}
_load_lock   = threading.Lock()


def _load_intel():
    global _blacklist
    if os.path.exists(INTEL_FILE):
        try:
            with open(INTEL_FILE, encoding="utf-8") as f:
                data = json.load(f)
                _blacklist.update(data.get("blacklist", []))
        except Exception:
            pass


def _save_intel():
    try:
        with open(INTEL_FILE, "w", encoding="utf-8") as f:
            json.dump({"blacklist": list(_blacklist)}, f, indent=2)
    except Exception:
        pass


def _is_bad_range(ip):
    return any(ip.startswith(prefix) for prefix in BAD_RANGES)


def _check_abuseipdb(ip):
    """Check AbuseIPDB if API key is set (optional)."""
    key = os.environ.get("ABUSEIPDB_KEY", "")
    if not key or not HTTP_OK:
        return None
    cached = _cache.get(ip)
    if cached and time.time() - cached["checked_at"] < 3600:
        return cached["score"]
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": key, "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=3) as r:
            body = json.loads(r.read())
            score = body.get("data", {}).get("abuseConfidenceScore", 0)
            _cache[ip] = {"score": score, "checked_at": time.time()}
            if score > 50:
                _blacklist.add(ip)
                _save_intel()
            return score
    except Exception:
        return None


class ThreatIntelDetector:

    def __init__(self):
        _load_intel()
        self._checked = set()

    def detect(self, events):
        findings = []
        now      = time.time()

        for ev in events:
            ip = ev.get("ip", "")
            if ip in ("", "local", "unknown", "127.0.0.1", "::1"):
                continue

            # Check static blacklist
            if ip in _blacklist:
                findings.append({
                    "type"          : "mitre_detection",
                    "technique_id"  : "T1583",
                    "technique_name": "Known Malicious Infrastructure",
                    "ip"            : ip,
                    "username"      : ev.get("username", "unknown"),
                    "severity"      : "CRITICAL",
                    "detail"        : f"IP {ip} is in known-bad threat intel database",
                    "timestamp"     : now,
                    "source"        : "mitre_t16_threat_intel"
                })
                continue

            # Check bad CIDR ranges
            if _is_bad_range(ip):
                _blacklist.add(ip)
                _save_intel()
                findings.append({
                    "type"          : "mitre_detection",
                    "technique_id"  : "T1583",
                    "technique_name": "Suspicious IP Range",
                    "ip"            : ip,
                    "username"      : ev.get("username", "unknown"),
                    "severity"      : "HIGH",
                    "detail"        : f"IP {ip} is in a known-bad CIDR range",
                    "timestamp"     : now,
                    "source"        : "mitre_t16_threat_intel"
                })
                continue

            # Async AbuseIPDB check (non-blocking)
            if ip not in self._checked:
                self._checked.add(ip)
                t = threading.Thread(target=_check_abuseipdb, args=(ip,), daemon=True)
                t.start()

        return findings
