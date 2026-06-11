# core/decision.py

def fuse(behavior, anomaly, graph_score, memory=None):
    w_b, w_a, w_g = 0.5, 0.3, 0.7
    if memory and len(memory) > 5:
        recent = memory[-10:]
        n = max(len(recent), 1)
        b = sum(1 for m in recent if "Suspicious user behavior" in str(m.get("result",{}).get("reasons",[])))
        a = sum(1 for m in recent if "Statistical anomaly"      in str(m.get("result",{}).get("reasons",[])))
        g = sum(1 for m in recent if "Multi-step attack"        in str(m.get("result",{}).get("reasons",[])))
        w_b = min(1.0, 0.5 + (b/n)*0.5)
        w_a = min(0.6, 0.3 + (a/n)*0.3)
        w_g = min(1.4, 0.7 + (g/n)*0.7)
    risk = min((behavior*w_b) + (anomaly*w_a) + (graph_score*w_g), 1.0)
    if risk > 0.8:   return "CRITICAL", risk
    elif risk > 0.5: return "HIGH",     risk
    elif risk > 0.3: return "MEDIUM",   risk
    else:            return "LOW",      risk

def decision_tree(result, events):
    types  = [e.get("type","") for e in events]
    risk   = result.get("risk", 0)
    level  = result.get("level","LOW")
    fails  = types.count("fail_login")
    admins = types.count("admin_access")
    sus    = types.count("suspicious_process")
    mitre  = types.count("mitre_detection")
    if sus > 0 and level in ("CRITICAL","HIGH"): return "KILL_PROCESS"
    if level == "CRITICAL":                       return "ISOLATE_SYSTEM"
    if fails > 5 and admins > 0:                  return "BLOCK_USER"
    if admins > 0 and risk > 0.5:                 return "BLOCK_USER"
    if fails > 5:                                  return "BLOCK_IP"
    if mitre > 3 or risk > 0.6:                   return "BLOCK_IP"
    if risk > 0.3:                                 return "MONITOR"
    return "ALLOW"
