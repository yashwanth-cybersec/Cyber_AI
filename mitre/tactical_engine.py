# mitre/tactical_engine.py  — MITRE ATT&CK Enterprise Tactical Engine (14/14)

import importlib
import time

DETECTOR_MODULES = [
    ("mitre.t03_initial_access",    "InitialAccessDetector",   "TA0001"),
    ("mitre.t04_execution",         "ExecutionDetector",        "TA0002"),
    ("mitre.t05_persistence",       "PersistenceDetector",      "TA0003"),
    ("mitre.t06_privilege_esc",     "PrivEscDetector",          "TA0004"),
    ("mitre.t07_defense_evasion",   "DefenseEvasionDetector",   "TA0005"),
    ("mitre.t08_credential_access", "CredentialAccessDetector", "TA0006"),
    ("mitre.t09_discovery",         "DiscoveryDetector",        "TA0007"),
    ("mitre.t10_lateral_movement",  "LateralMovementDetector",  "TA0008"),
    ("mitre.t11_collection",        "CollectionDetector",       "TA0009"),
    ("mitre.t12_c2",                "C2Detector",               "TA0011"),
    ("mitre.t13_exfiltration",      "ExfiltrationDetector",     "TA0010"),
    ("mitre.t14_impact",            "ImpactDetector",           "TA0040"),
    ("mitre.t15_honeypot",          "HoneypotDetector",         "TA0043"),
    ("mitre.t16_threat_intel",      "ThreatIntelDetector",      "TA0042"),
]

_detectors  = []
_loaded     = []
_skipped    = []
_hit_counts = {}


def load_all_detectors():
    global _detectors, _loaded, _skipped
    _detectors, _loaded, _skipped = [], [], []
    for mod_name, cls_name, tactic in DETECTOR_MODULES:
        try:
            mod = importlib.import_module(mod_name)
            cls = getattr(mod, cls_name)
            obj = cls()
            _detectors.append((obj, tactic, mod_name))
            _loaded.append(mod_name)
        except Exception as e:
            _skipped.append((mod_name, str(e)))
    print(f"  [TacticalEngine] Loaded  : {len(_loaded)} / {len(DETECTOR_MODULES)} detectors")
    if _skipped:
        print(f"  [TacticalEngine] Skipped : {len(_skipped)}")
        for name, err in _skipped:
            print(f"    SKIP {name}: {err}")
    return len(_loaded)


def run_all_detectors(events):
    findings = []
    now      = time.time()
    for det, tactic, mod_name in _detectors:
        try:
            results = det.detect(events)
            for r in (results or []):
                r.setdefault("tactic",    tactic)
                r.setdefault("type",      "mitre_detection")
                r.setdefault("timestamp", now)
                tid = r.get("technique_id", "")
                if tid:
                    _hit_counts[tid] = _hit_counts.get(tid, 0) + 1
                findings.append(r)
        except Exception:
            pass
    return findings


def get_coverage_summary():
    return {
        "loaded_detectors"  : len(_loaded),
        "total_detectors"   : len(DETECTOR_MODULES),
        "skipped_detectors" : len(_skipped),
        "loaded_tactics"    : [t for _, t, __ in _detectors],
        "coverage_pct"      : round(len(_loaded) / len(DETECTOR_MODULES) * 100),
        "hit_counts"        : dict(_hit_counts),
    }
