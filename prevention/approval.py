# prevention/approval.py
import time
import uuid
import hashlib
from collections import deque
from datetime import datetime

ADMIN_PIN_HASH    = hashlib.sha256(b"CyberAI2024").hexdigest()
pending_approvals = {}
approval_history  = deque(maxlen=500)

def create_approval_request(action_type, target, detail, threat_level, triggered_by):
    aid = str(uuid.uuid4())[:8].upper()
    pending_approvals[aid] = {
        "id": aid,
        "action_type": action_type,
        "target": str(target),
        "detail": detail,
        "threat_level": threat_level,
        "triggered_by": triggered_by,
        "created_at": datetime.now().strftime("%H:%M:%S"),
        "created_ts": time.time(),
        "status": "PENDING_USER",
        "user_approved": False,
        "user_approved_at": None,
        "admin_approved": False,
        "admin_approved_at": None,
        "executed": False,
        "executed_at": None,
        "result": None,
        "expires_at": time.time() + 300,   # ← FIXED: 5 minutes (was 100)
    }
    return aid

def user_approve(aid):
    if aid not in pending_approvals:
        return {"success": False, "error": "Not found"}
    r = pending_approvals[aid]
    if time.time() > r["expires_at"]:
        r["status"] = "EXPIRED"
        return {"success": False, "error": "Expired"}
    r["user_approved"] = True
    r["user_approved_at"] = datetime.now().strftime("%H:%M:%S")
    r["status"] = "PENDING_ADMIN"
    return {"success": True, "approval_id": aid, "next_step": "Admin PIN required", "status": "PENDING_ADMIN"}

def admin_approve(aid, pin):
    if aid not in pending_approvals:
        return {"success": False, "error": "Not found"}
    r = pending_approvals[aid]
    if r["status"] != "PENDING_ADMIN":
        return {"success": False, "error": f"Status is {r['status']}"}
    if time.time() > r["expires_at"]:
        r["status"] = "EXPIRED"
        return {"success": False, "error": "Expired"}
    if hashlib.sha256(pin.encode()).hexdigest() != ADMIN_PIN_HASH:
        return {"success": False, "error": "Invalid admin PIN"}
    r["admin_approved"] = True
    r["admin_approved_at"] = datetime.now().strftime("%H:%M:%S")
    r["status"] = "APPROVED"
    return {"success": True, "approval_id": aid, "status": "APPROVED", "message": "Both approvals received"}

def reject(aid, reason=""):
    if aid not in pending_approvals:
        return {"success": False, "error": "Not found"}
    r = pending_approvals[aid]
    r["status"] = "REJECTED"
    r["result"] = {"rejected_reason": reason}
    approval_history.append(dict(r))
    del pending_approvals[aid]
    return {"success": True, "approval_id": aid, "status": "REJECTED"}

def mark_executed(aid, result):
    if aid in pending_approvals:
        r = pending_approvals[aid]
        r.update({
            "status": "EXECUTED",
            "executed": True,
            "executed_at": datetime.now().strftime("%H:%M:%S"),
            "result": result
        })
        approval_history.append(dict(r))
        del pending_approvals[aid]

def get_pending():
    now = time.time()
    expired = []
    for aid, r in pending_approvals.items():
        if now > r["expires_at"]:
            r["status"] = "EXPIRED"
            expired.append(aid)
    for aid in expired:
        approval_history.append(dict(pending_approvals[aid]))
        del pending_approvals[aid]
    return sorted(pending_approvals.values(), key=lambda x: -x["created_ts"])

def get_history():
    return list(approval_history)