# security/data_security.py  — File Integrity Monitor + Backup + Auth

import os
import json
import time
import hashlib
import shutil
from datetime import datetime

_HERE         = os.path.dirname(os.path.abspath(__file__))
_ROOT         = os.path.dirname(_HERE)           # cyber_ai/  (one level up from security/)
BASELINE_FILE = os.path.join(_ROOT, "fim_baseline.json")
AUTH_FILE     = os.path.join(_ROOT, "auth.json")
BACKUP_DIR    = os.path.join(_ROOT, "backups")

MONITOR_EXTS  = {".py", ".json", ".html", ".txt", ".cfg"}
SKIP_DIRS     = {"__pycache__", ".git", "backups", "node_modules"}

_baseline     = {}
_fim_alerts   = []
_users        = {}


# ── File Integrity Monitor ──────────────────────────────────────────────

def _hash_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def build_baseline(root="."):
    global _baseline
    _baseline = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if any(fname.endswith(ext) for ext in MONITOR_EXTS):
                fpath = os.path.normpath(os.path.join(dirpath, fname))
                h     = _hash_file(fpath)
                if h:
                    _baseline[fpath] = {"hash": h, "ts": time.time()}
    try:
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(_baseline, f, indent=2)
    except Exception:
        pass
    print(f"  [FIM] Baseline: {len(_baseline)} files monitored")
    return len(_baseline)


def load_baseline():
    global _baseline
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, encoding="utf-8") as f:
                _baseline = json.load(f)
        except Exception:
            _baseline = {}
    if not _baseline:
        build_baseline()


def check_integrity(root="."):
    if not _baseline:
        load_baseline()
    alerts = []
    now    = time.time()

    # Check existing files
    for fpath, info in _baseline.items():
        if not os.path.exists(fpath):
            alert = {"type":"DELETED","file":fpath,"ts":now,
                     "detail":f"Monitored file deleted: {fpath}","severity":"CRITICAL"}
            alerts.append(alert)
            _fim_alerts.append(alert)
            continue
        current_hash = _hash_file(fpath)
        if current_hash and current_hash != info.get("hash",""):
            alert = {"type":"MODIFIED","file":fpath,"ts":now,
                     "detail":f"File modified: {fpath}","severity":"HIGH"}
            alerts.append(alert)
            _fim_alerts.append(alert)
            _baseline[fpath]["hash"] = current_hash

    # Check for new files
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if any(fname.endswith(ext) for ext in MONITOR_EXTS):
                fpath = os.path.normpath(os.path.join(dirpath, fname))
                if fpath not in _baseline:
                    h = _hash_file(fpath)
                    if h:
                        _baseline[fpath] = {"hash": h, "ts": now}
                        alert = {"type":"NEW_FILE","file":fpath,"ts":now,
                                 "detail":f"New file detected: {fpath}","severity":"MEDIUM"}
                        alerts.append(alert)
                        _fim_alerts.append(alert)

    return alerts


def get_fim_alerts(limit=50):
    return _fim_alerts[-limit:]


# ── Backup ──────────────────────────────────────────────────────────────

BACKUP_FILES = ["memory.json","audit_log.json","fim_baseline.json",
                "memory_threat_intel.json","identity_baseline.json"]


def create_backup():
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest    = os.path.join(BACKUP_DIR, ts)
    os.makedirs(dest, exist_ok=True)
    backed  = []
    for fname in BACKUP_FILES:
        if os.path.exists(fname):
            shutil.copy2(fname, os.path.join(dest, fname))
            size = os.path.getsize(fname)
            backed.append({"file": fname, "size": size,
                           "size_kb": round(size/1024,1)})
    return {"timestamp": ts, "path": dest, "files": backed, "count": len(backed)}


def list_backups():
    """List all backups with their file names"""
    if not os.path.exists(BACKUP_DIR):
        return []
    backups = []
    for entry in sorted(os.listdir(BACKUP_DIR), reverse=True)[:20]:
        full = os.path.join(BACKUP_DIR, entry)
        if os.path.isdir(full):
            files = []
            total = 0
            for f in os.listdir(full):
                fpath = os.path.join(full, f)
                if os.path.isfile(fpath):
                    size = os.path.getsize(fpath)
                    total += size
                    files.append({"name": f, "size": size})
            
            # Sort files for consistent display
            files.sort(key=lambda x: x["name"])
            
            backups.append({
                "timestamp": entry,
                "path": full,
                "file_count": len(files),
                "total_kb": round(total / 1024, 1),
                "files": files,  # Add file list
            })
    return backups


def get_backup_files(timestamp):
    """Get list of files in a backup with details"""
    path = os.path.join(BACKUP_DIR, timestamp)
    if not os.path.isdir(path):
        return []
    result = []
    for fname in os.listdir(path):
        fpath = os.path.join(path, fname)
        if os.path.isfile(fpath):
            stat = os.stat(fpath)
            result.append({
                "name": fname,
                "size": stat.st_size,
                "size_kb": round(stat.st_size / 1024, 1),
                "modified": stat.st_mtime,
                "path": fpath
            })
    # Sort by name for consistent display
    result.sort(key=lambda x: x["name"])
    return result

# ── Auth ────────────────────────────────────────────────────────────────

def _load_users():
    global _users
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, encoding="utf-8") as f:
                _users = json.load(f)
            return
        except Exception:
            pass
    # Create default user
    _users = {"yashwanth": hashlib.sha256(b"CyberAI2024").hexdigest()}
    _save_users()
    print("  [Auth] Created user 'yashwanth' with password 'CyberAI2024'")


def _save_users():
    try:
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(_users, f, indent=2)
    except Exception:
        pass


def verify_user(username, password):
    if not _users:
        _load_users()
    ph = hashlib.sha256(password.encode()).hexdigest()
    return _users.get(username) == ph


def init_security():
    """Called at startup."""
    _load_users()
    load_baseline()
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup = create_backup()
    print(f"  [Backup] {backup['count']} files → {BACKUP_DIR}/{backup['timestamp']}")
    return True
