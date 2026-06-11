# advanced/identity_anomaly_detector.py  — Behavioral Identity Anomaly Detection

import time
import json
import os
from collections import defaultdict
from datetime import datetime

PROFILE_FILE = "identity_baseline.json"
MIN_LOGINS   = 5    # minimum before scoring anomalies


class IdentityAnomalyDetector:

    def __init__(self):
        self._profiles = defaultdict(lambda: {
            "login_hours"  : [],
            "login_ips"    : [],
            "fail_counts"  : [],
            "login_count"  : 0,
            "last_seen"    : 0,
        })
        self._alerts_sent = set()
        self._load()

    def _load(self):
        if os.path.exists(PROFILE_FILE):
            try:
                with open(PROFILE_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                for user, profile in data.items():
                    self._profiles[user].update(profile)
            except Exception:
                pass

    def _save(self):
        try:
            data = {u: dict(p) for u, p in self._profiles.items()}
            with open(PROFILE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def detect(self, events):
        findings = []
        now      = time.time()
        hour     = datetime.now().hour

        for ev in events:
            etype = ev.get("type", "")
            user  = ev.get("username", "")
            ip    = ev.get("ip", "")

            if not user or user in ("unknown","SYSTEM","system",""):
                continue

            prof = self._profiles[user]

            # Update profile on successful login
            if etype == "login_success":
                prof["login_count"] += 1
                prof["last_seen"]    = now
                if hour not in prof["login_hours"]:
                    prof["login_hours"].append(hour)
                    if len(prof["login_hours"]) > 48:
                        prof["login_hours"] = prof["login_hours"][-48:]
                if ip not in prof["login_ips"]:
                    prof["login_ips"].append(ip)
                    if len(prof["login_ips"]) > 20:
                        prof["login_ips"] = prof["login_ips"][-20:]
                self._save()

            # Anomaly detection — only after baseline established
            if prof["login_count"] >= MIN_LOGINS:

                # After-hours login (outside 07:00–22:00)
                if etype == "login_success" and (hour < 7 or hour > 22):
                    key = f"afterhours_{user}_{hour}"
                    if key not in self._alerts_sent:
                        self._alerts_sent.add(key)
                        findings.append({
                            "type"          : "mitre_detection",
                            "technique_id"  : "T1078",
                            "technique_name": "After-Hours Login Anomaly",
                            "ip"            : ip,
                            "username"      : user,
                            "severity"      : "HIGH",
                            "detail"        : f"User '{user}' logged in at {hour:02d}:00 (unusual hour)",
                            "timestamp"     : now,
                            "source"        : "identity_anomaly_detector"
                        })

                # Login from new IP not seen before
                if etype == "login_success" and ip not in ("local","","unknown","127.0.0.1"):
                    if ip not in prof["login_ips"] and len(prof["login_ips"]) >= 3:
                        key = f"newip_{user}_{ip}"
                        if key not in self._alerts_sent:
                            self._alerts_sent.add(key)
                            findings.append({
                                "type"          : "mitre_detection",
                                "technique_id"  : "T1078.003",
                                "technique_name": "New Source IP — Possible Stolen Credentials",
                                "ip"            : ip,
                                "username"      : user,
                                "severity"      : "HIGH",
                                "detail"        : f"User '{user}' logging in from unseen IP {ip}",
                                "timestamp"     : now,
                                "source"        : "identity_anomaly_detector"
                            })

        return findings
