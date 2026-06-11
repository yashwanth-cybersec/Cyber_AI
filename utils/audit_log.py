# utils/audit_log.py
import json, os
from datetime import datetime
FILE = "audit_log.json"

def log_action(action_type, target, approval_id, result, approved_by="user+admin"):
    entry = {
        "timestamp":   datetime.now().isoformat(),
        "approval_id": approval_id,
        "action_type": action_type,
        "target":      str(target),
        "approved_by": approved_by,
        "success":     result.get("success", False),
        "output":      str(result.get("output", result.get("error","")))[:300],
        "result":      result,
    }
    log = _load(); log.append(entry)
    try:
        with open(FILE,"w",encoding="utf-8") as f: json.dump(log[-500:], f, indent=2, default=str)
    except Exception: pass

def get_log(limit=50): return _load()[-limit:]
def _load():
    if os.path.exists(FILE):
        try:
            with open(FILE,encoding="utf-8") as f: return json.load(f)
        except Exception: pass
    return []
