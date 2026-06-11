# prevention/engine.py
import time
from prevention.approval import create_approval_request, mark_executed, pending_approvals
from prevention.actions import block_ip, kill_process, disable_user, isolate_network
from utils.audit_log import log_action

_recent = {}

def propose_prevention(result, events):
    """
    Analyze orchestrator result and events, and create approval requests
    for actions like BLOCK_IP, DISABLE_USER, ISOLATE_NETWORK.
    Returns a list of approval IDs created.
    """
    level = result.get("level", "LOW")
    action = result.get("action", "MONITOR")
    if level not in ("CRITICAL", "HIGH", "MEDIUM"):
        return []

    proposals = []
    now = time.time()

    # Extract unique IPs and usernames from events
    ips = list({e.get("ip", "") for e in events if e.get("ip", "") not in ("", "local", "unknown", "127.0.0.1", "::1")})
    users = list({e.get("username", "") for e in events if e.get("username", "") not in ("", "unknown", "SYSTEM")})

    detail = " | ".join(result.get("reasons", [])[:2])

    # Propose BLOCK_IP for top IPs (up to 2) with cooldown
    for ip in ips[:2]:
        if now - _recent.get(ip, 0) > 60:
            aid = create_approval_request(
                "BLOCK_IP", ip,
                f"Threat from {ip}. {detail}",
                level, action
            )
            proposals.append(aid)
            _recent[ip] = now

    # Propose DISABLE_USER if action suggests it and users exist
    if action == "BLOCK_USER" and users:
        u = users[0]
        key = f"user_{u}"
        if now - _recent.get(key, 0) > 300:
            aid = create_approval_request(
                "DISABLE_USER", u,
                f"Malicious activity by {u}. {detail}",
                level, action
            )
            proposals.append(aid)
            _recent[key] = now

    # Propose ISOLATE_NETWORK for critical ransomware/impact actions
    if action in ("ISOLATE_SYSTEM", "STOP_RANSOMWARE"):
        key = "isolate"
        if now - _recent.get(key, 0) > 600:
            aid = create_approval_request(
                "ISOLATE_NETWORK", "ALL_INTERFACES",
                f"CRITICAL threat. {detail}",
                "CRITICAL", action
            )
            proposals.append(aid)
            _recent[key] = now

    return proposals


def execute_approved(aid, rec):
    """
    Execute the approved action.
    Returns a result dict with at least {"success": bool, ...}.
    """
    action = rec.get("action_type")
    target = rec.get("target")
    triggered_by = rec.get("triggered_by", "system")
    detail = rec.get("detail", "")

    result = {"success": False, "error": "Unknown action"}

    try:
        if action == "BLOCK_IP":
            result = block_ip(target)
        elif action == "KILL_PROCESS":
            # target can be PID or process name
            if target and str(target).isdigit():
                result = kill_process(pid=int(target))
            else:
                result = kill_process(name=target)
        elif action == "DISABLE_USER":
            result = disable_user(target)
        elif action == "ISOLATE_NETWORK":
            result = isolate_network()
        else:
            result = {"success": False, "error": f"Unsupported action: {action}"}
    except Exception as e:
        result = {"success": False, "error": str(e)}

    # Mark the approval as executed (moves to history)
    mark_executed(aid, result)

    # Log to audit trail
    try:
        log_action(
            action,
            target,
            f"APPROVAL_{aid}",
            result,
            approved_by=f"{triggered_by}+admin"
        )
    except Exception:
        pass

    return result


def execute_pending_approved():
    """
    Optional: Execute all pending approvals that have been fully approved.
    Called by the monitoring engine or a background thread.
    """
    executed = []
    # Make a copy of items because we may modify during iteration
    for aid, rec in list(pending_approvals.items()):
        if rec.get("status") == "APPROVED" and not rec.get("executed"):
            result = execute_approved(aid, rec)
            executed.append((aid, result))
    return execute