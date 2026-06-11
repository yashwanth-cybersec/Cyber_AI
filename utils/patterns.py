# utils/patterns.py
import time
def detect_repeated_attack(memory, threshold=3, window=120):
    if not memory: return None
    now    = time.time()
    recent = [m for m in memory if now - m.get("time",0) < window]
    return "REPEATED_ATTACK" if len(recent) >= threshold else None
