# prevention/actions.py
# prevention/actions.py
import os
import platform
import subprocess
import socket
import json

try:
    import psutil
    PS_OK = True
except ImportError:
    PS_OK = False

OS = platform.system()

# Use absolute path for blocked_ips.json in the main cyber_ai directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCKED_IPS_FILE = os.path.join(BASE_DIR, 'blocked_ips.json')

def _load_blocked_ips():
    """Load persistently blocked IPs from JSON file."""
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                data = json.load(f)
                print(f"  [Actions] Loaded {len(data)} blocked IPs from {BLOCKED_IPS_FILE}")
                return set(data)
    except Exception as e:
        print(f"  [Actions] Error loading blocked IPs: {e}")
    return set()

def _save_blocked_ips(blocked_set):
    """Save blocked IPs set to JSON file."""
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(list(blocked_set), f)
        print(f"  [Actions] Saved {len(blocked_set)} blocked IPs to {BLOCKED_IPS_FILE}")
    except Exception as e:
        print(f"  [Actions] Error saving blocked IPs: {e}")

# ... rest of the file unchanged ...
def _run(cmd, timeout=10):
    """Helper to run shell commands."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout or r.stderr or "").strip()[:300]
    except subprocess.TimeoutExpired:
        return False, "Timed out"
    except PermissionError:
        return False, "Permission denied - run as Administrator/root"
    except Exception as e:
        return False, str(e)

def _is_ipv6(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (socket.error, OSError):
        return False

def _is_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except (socket.error, OSError):
        return False

def _valid_ip(ip):
    ip = ip.strip()
    return _is_ipv4(ip) or _is_ipv6(ip)

def block_ip(ip):
    """Block an IP address using Windows Firewall or iptables, with persistence."""
    ip = ip.strip()
    if not _valid_ip(ip):
        return {"success": False, "error": f"Invalid IP: {ip}"}
    
    # Check persistent store first
    blocked = _load_blocked_ips()
    if ip in blocked:
        return {"success": True, "action": "BLOCK_IP", "target": ip, "output": "Already blocked"}

    is_v6 = _is_ipv6(ip)
    if OS == "Windows":
        safe = ip.replace(":", "_").replace(".", "_")
        name = f"CyberAI_Block_{safe}"
        ok, out = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={name}", "dir=in", "action=block",
                        f"remoteip={ip}", "enable=yes"])
        if ok:
            blocked.add(ip)
            _save_blocked_ips(blocked)
        return {"success": ok, "action": "BLOCK_IP", "target": ip, "output": out}
    elif OS == "Linux":
        tool = "ip6tables" if is_v6 else "iptables"
        ok, out = _run([tool, "-A", "INPUT", "-s", ip, "-j", "DROP"])
        if ok:
            blocked.add(ip)
            _save_blocked_ips(blocked)
        return {"success": ok, "action": "BLOCK_IP", "target": ip, "output": out}
    return {"success": False, "error": "Unsupported OS"}

def unblock_ip(ip):
    """Remove firewall rule for an IP and update persistent store."""
    ip = ip.strip()
    if not _valid_ip(ip):
        return {"success": False, "error": f"Invalid IP: {ip}"}
    
    blocked = _load_blocked_ips()
    if ip not in blocked:
        return {"success": False, "error": f"IP {ip} is not currently blocked"}

    is_v6 = _is_ipv6(ip)
    if OS == "Windows":
        safe = ip.replace(":", "_").replace(".", "_")
        name = f"CyberAI_Block_{safe}"
        ok, out = _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={name}"])
        if ok:
            blocked.discard(ip)
            _save_blocked_ips(blocked)
        return {"success": ok, "action": "UNBLOCK_IP", "target": ip, "output": out}
    elif OS == "Linux":
        tool = "ip6tables" if is_v6 else "iptables"
        ok, out = _run([tool, "-D", "INPUT", "-s", ip, "-j", "DROP"])
        if ok:
            blocked.discard(ip)
            _save_blocked_ips(blocked)
        return {"success": ok, "action": "UNBLOCK_IP", "target": ip, "output": out}
    return {"success": False, "error": "Unsupported OS"}

def get_blocked_ips():
    """Return a list of currently blocked IPs (from persistent store)."""
    return sorted(list(_load_blocked_ips()))

def kill_process(pid=None, name=None):
    if not PS_OK:
        return {"success": False, "error": "psutil not installed"}
    killed = []
    if pid:
        try:
            p = psutil.Process(int(pid))
            nm = p.name()
            p.kill()
            killed.append({"pid": pid, "name": nm})
        except psutil.NoSuchProcess:
            return {"success": False, "error": f"PID {pid} not found"}
        except psutil.AccessDenied:
            return {"success": False, "error": f"Access denied for PID {pid}"}
    elif name:
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if name.lower() in (p.info["name"] or "").lower():
                    p.kill()
                    killed.append({"pid": p.info["pid"], "name": p.info["name"]})
            except Exception:
                pass
    if killed:
        return {"success": True, "action": "KILL_PROCESS", "killed": killed}
    return {"success": False, "error": "No matching process"}

def disable_user(username):
    if not username or username.lower() in ("system", "nt authority\\system", ""):
        return {"success": False, "error": "Cannot disable system account"}
    if OS == "Windows":
        ok, out = _run(["net", "user", username, "/active:no"])
        return {"success": ok, "action": "DISABLE_USER", "username": username, "output": out}
    elif OS == "Linux":
        ok, out = _run(["usermod", "-L", username])
        return {"success": ok, "action": "DISABLE_USER", "username": username, "output": out}
    return {"success": False, "error": "Unsupported OS"}

def isolate_network():
    if OS == "Windows":
        ok, out = _run(["netsh", "advfirewall", "set", "allprofiles",
                        "firewallpolicy", "blockinbound,blockoutbound"])
        return {"success": ok, "action": "ISOLATE_NETWORK", "output": out, "warning": "System isolated"}
    elif OS == "Linux":
        results = []
        for iface in os.listdir("/sys/class/net/"):
            if iface == "lo":
                continue
            ok, out = _run(["ip", "link", "set", iface, "down"])
            if ok:
                results.append(iface)
        return {"success": bool(results), "action": "ISOLATE_NETWORK", "disabled": results}
    return {"success": False, "error": "Unsupported OS"}