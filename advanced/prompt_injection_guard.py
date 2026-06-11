# advanced/prompt_injection_guard.py  — AI Prompt Injection Defense (MITRE ATLAS AML.T0051)

import re
import time

INJECTION_PATTERNS = [
    (r"ignore previous instructions",     "Classic ignore override",          "CRITICAL"),
    (r"ignore all instructions",           "Ignore-all override",              "CRITICAL"),
    (r"you are now (?:in )?(?:dan|jailbreak|developer mode)", "Jailbreak attempt", "CRITICAL"),
    (r"\[INST\]|\[\/INST\]|\<s\>|\<\/s\>","LLM token injection",             "HIGH"),
    (r"system prompt|system message",      "System prompt extraction",         "HIGH"),
    (r"reveal (?:your|the) (?:prompt|instructions|system)", "Prompt extraction","HIGH"),
    (r"disregard (?:all )?(?:previous|prior|earlier)",      "Disregard override","HIGH"),
    (r"act as (?:a malicious|an evil|an unethical)",        "Role hijack",       "HIGH"),
    (r"risk_score\s*=\s*0|set.*risk.*to.*0",               "Score manipulation","CRITICAL"),
    (r"action\s*=\s*['\"]?allow['\"]?",                    "Action override",   "CRITICAL"),
    (r"\x00|\u200b|\u200c|\u200d|\ufeff",                  "Hidden characters", "HIGH"),
    (r"\\u00|%00",                                          "Null byte injection","HIGH"),
    (r"<script|javascript:|onerror=",                       "XSS injection",     "MEDIUM"),
    (r"SELECT.*FROM|DROP TABLE|INSERT INTO",               "SQL injection",     "MEDIUM"),
    (r"eval\(|exec\(|__import__",                          "Code injection",    "HIGH"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), label, sev)
             for p, label, sev in INJECTION_PATTERNS]

_blocked_count = 0
_blocked_log   = []   # last 100 blocked events


class PromptInjectionGuard:

    def __init__(self):
        self._blocked = 0

    def sanitize(self, events):
        """
        Scan every event for injection patterns.
        Returns (clean_events, injection_findings).
        """
        clean    = []
        findings = []
        now      = time.time()

        for ev in events:
            injected, matched_pattern, matched_sev = self._scan_event(ev)

            if injected:
                global _blocked_count
                _blocked_count += 1
                self._blocked  += 1

                finding = {
                    "type"          : "mitre_detection",
                    "technique_id"  : "AML.T0051",
                    "technique_name": "Prompt / Data Injection Attack",
                    "ip"            : ev.get("ip", "unknown"),
                    "username"      : ev.get("username", "unknown"),
                    "severity"      : matched_sev,
                    "detail"        : f"Injection blocked: {matched_pattern}",
                    "original_type" : ev.get("type",""),
                    "timestamp"     : now,
                    "source"        : "prompt_injection_guard",
                    "blocked"       : True,
                }
                findings.append(finding)
                _blocked_log.append(finding)
                if len(_blocked_log) > 100:
                    del _blocked_log[:-100]

                # Sanitize the event instead of dropping it
                safe_ev = {k: self._clean_value(v) for k, v in ev.items()}
                clean.append(safe_ev)
            else:
                clean.append(ev)

        return clean, findings

    def _scan_event(self, ev):
        text = " ".join(str(v) for v in ev.values()).lower()
        for pattern, label, sev in _COMPILED:
            if pattern.search(text):
                return True, label, sev
        return False, "", ""

    def _clean_value(self, val):
        if not isinstance(val, str):
            return val
        clean = val
        for pattern, _, _ in _COMPILED:
            clean = pattern.sub("[SANITIZED]", clean)
        return clean

    def detect(self, events):
        """Called by advanced_engine — returns only the injection findings."""
        _, findings = self.sanitize(events)
        return findings

    def get_stats(self):
        return {
            "total_blocked"  : _blocked_count,
            "session_blocked": self._blocked,
            "recent_log"     : _blocked_log[-20:],
        }


def test_injection(payload):
    """Test a payload string — returns True if it would be blocked."""
    guard = PromptInjectionGuard()
    fake_event = {"type": "test", "detail": payload, "ip": "local", "username": "test"}
    blocked, matched, sev = guard._scan_event(fake_event)
    return {"blocked": blocked, "pattern": matched, "severity": sev}
