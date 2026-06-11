# core/orchestrator.py
from agents.behavior_agent import analyze
from agents.anomaly_agent  import AnomalyAgent
from core.decision         import fuse, decision_tree
from utils.patterns        import detect_repeated_attack

class Orchestrator:
    def __init__(self):
        self.anomaly = AnomalyAgent()

    def process(self, events, feature, graph_score, memory=None):
        if memory is None: memory = []
        behavior_score = analyze(events)
        anomaly_score  = self.anomaly.predict(feature)
        level, risk    = fuse(behavior_score, anomaly_score, graph_score, memory)

        reasons = []
        if behavior_score > 0.3: reasons.append("Suspicious user behavior detected")
        if graph_score > 0.5:    reasons.append("Multi-step attack path detected")
        if anomaly_score > 0:    reasons.append("Statistical anomaly detected")
        if len(events) > 3:      reasons.append(f"High intensity: {len(events)} events")
        for e in events:
            if e.get("type") == "mitre_detection":
                tid  = e.get("technique_id","")
                name = e.get("technique_name","")
                if tid: reasons.append(f"MITRE {tid}: {name}")

        result = {"level": level, "risk": round(risk,3), "reasons": list(dict.fromkeys(reasons))[:6]}
        action = decision_tree(result, events)

        pattern = detect_repeated_attack(memory)
        if pattern:
            if risk > 0.7:   action = "BLOCK_NETWORK"
            elif risk > 0.5: action = "BLOCK_IP"
            elif risk > 0.3: action = "MONITOR"
        elif len(memory) > 10:
            import time
            now    = time.time()
            recent = [m for m in memory if now - m.get("time",0) < 120]
            if len(recent) > 3:   action = "BLOCK_IP"
            elif len(recent) > 1: action = "MONITOR"
            else:                 action = "ALLOW"

        result["action"] = action
        return result
