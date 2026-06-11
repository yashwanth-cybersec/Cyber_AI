# agents/behavior_agent.py
from collections import Counter

def analyze(events):
    if not events: return 0.0
    score  = 0.0
    types  = [e.get("type","") for e in events]
    c      = Counter(types)
    fails  = c.get("fail_login", 0)
    if fails >= 10:   score += 0.5
    elif fails >= 5:  score += 0.4
    elif fails >= 3:  score += 0.2
    if c.get("admin_access",0) > 0: score += 0.4
    if fails > 3 and c.get("admin_access",0) > 0: score += 0.2
    if c.get("suspicious_process",0) > 0: score += 0.5
    ips = len({e.get("ip","") for e in events if e.get("ip","") not in ("","local","unknown","127.0.0.1")})
    if ips >= 4:   score += 0.3
    elif ips >= 2: score += 0.15
    if c.get("cpu_spike",0) > 0:   score += 0.2
    if c.get("port_connect",0) > 5: score += 0.15
    mitre = c.get("mitre_detection",0)
    if mitre > 5:   score += 0.4
    elif mitre > 2: score += 0.25
    elif mitre > 0: score += 0.1
    return min(score, 1.0)
