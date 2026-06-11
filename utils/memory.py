# utils/memory.py
import json, os, time
FILE     = "memory.json"
memory_db = []
if os.path.exists(FILE):
    try:
        with open(FILE,"r",encoding="utf-8") as f: memory_db = json.load(f)
    except Exception: memory_db = []

def _safe(obj):
    try: json.dumps(obj); return obj
    except Exception: return str(obj)

def store_attack(result, events):
    entry = {
        "result": {k: _safe(v) for k,v in result.items()},
        "events": [{k: _safe(v) for k,v in e.items()} for e in events[:5]],
        "time":   time.time()
    }
    memory_db.append(entry)
    if len(memory_db) > 200: del memory_db[:-200]
    try:
        with open(FILE,"w",encoding="utf-8") as f: json.dump(memory_db, f, indent=2, default=str)
    except Exception: pass

def get_memory_size(): return len(memory_db)
def clear_memory():
    global memory_db; memory_db.clear()
    try:
        with open(FILE,"w",encoding="utf-8") as f: json.dump([], f)
    except Exception: pass
