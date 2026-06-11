# advanced/advanced_engine.py  — Advanced Threat Engine Coordinator

from advanced.polymorphic_detector    import PolymorphicDetector
from advanced.identity_anomaly_detector import IdentityAnomalyDetector
from advanced.prompt_injection_guard  import PromptInjectionGuard

_detectors = {}
_guard     = None


def load_advanced_detectors():
    global _detectors, _guard
    _detectors = {
        "PolymorphicDetector"    : PolymorphicDetector(),
        "IdentityAnomalyDetector": IdentityAnomalyDetector(),
    }
    _guard = PromptInjectionGuard()
    print(f"  [Advanced] Loaded: {', '.join(_detectors.keys())}, PromptInjectionGuard")
    return len(_detectors) + 1


def run_advanced_detectors(events):
    """
    1. Run prompt injection guard FIRST (sanitize inputs)
    2. Run polymorphic + identity detectors on clean events
    Returns (clean_events, all_findings)
    """
    all_findings = []

    # Step 1: injection guard
    if _guard:
        events, inj_findings = _guard.sanitize(events)
        all_findings.extend(inj_findings)

    # Step 2: other detectors
    for name, det in _detectors.items():
        try:
            results = det.detect(events)
            all_findings.extend(results or [])
        except Exception:
            pass

    return events, all_findings


def get_advanced_status():
    status = {"enabled": bool(_detectors), "detectors": {}}
    for name, det in _detectors.items():
        status["detectors"][name] = {
            "loaded": True,
            "type"  : name,
        }
    if _guard:
        try:
            stats = _guard.get_stats()
            status["detectors"]["PromptInjectionGuard"] = {
                "loaded" : True,
                "blocked": stats.get("total_blocked", 0),
            }
        except Exception:
            pass
    return status
