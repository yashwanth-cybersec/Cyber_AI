# prevention/security_advisor.py
import os, socket, platform, subprocess, ctypes, time
from utils.scanner import scan_local_ports

OS = platform.system()

VULN_DB = {
    22:   {"id":"SSH-001","title":"SSH Port Open","severity":"HIGH",
           "desc":"SSH (port 22) allows remote login. Disable if unused.",
           "steps":["Open Terminal","Run: sudo systemctl stop ssh","Run: sudo systemctl disable ssh","Verify: netstat -tlnp | grep :22"],
           "cmd_win":"netsh advfirewall firewall add rule name=\"Block SSH\" dir=in action=block protocol=TCP localport=22",
           "cmd_linux":"sudo systemctl stop ssh && sudo systemctl disable ssh"},
    23:   {"id":"CRIT-001","title":"Telnet Open — CRITICAL","severity":"CRITICAL",
           "desc":"Telnet is completely unencrypted. Disable immediately and use SSH.",
           "steps":["Disable the Telnet service","Block port 23 in firewall","Switch all users to SSH"],
           "cmd_win":"netsh advfirewall firewall add rule name=\"Block Telnet\" dir=in action=block protocol=TCP localport=23",
           "cmd_linux":"sudo systemctl stop telnetd && sudo ufw deny 23"},
    80:   {"id":"WEB-001","title":"HTTP Web Server Running","severity":"MEDIUM",
           "desc":"Port 80 (HTTP) is open. Ensure traffic is redirected to HTTPS.",
           "steps":["Verify the web server is intentional","Enable HTTPS (port 443)","Redirect HTTP → HTTPS","Keep web server software updated"],
           "cmd_win":"netsh advfirewall firewall add rule name=\"Block HTTP\" dir=in action=block protocol=TCP localport=80",
           "cmd_linux":"sudo ufw deny 80"},
    443:  {"id":"WEB-002","title":"HTTPS Server Running","severity":"LOW",
           "desc":"Port 443 (HTTPS) is open. Verify your TLS certificate is valid and up to date.",
           "steps":["Check certificate expiry: openssl s_client -connect localhost:443","Ensure TLS 1.2+ is enforced","Disable weak cipher suites"],
           "cmd_win":"","cmd_linux":"openssl s_client -connect localhost:443 -brief"},
    3306: {"id":"DB-001","title":"MySQL Database Exposed","severity":"CRITICAL",
           "desc":"MySQL (port 3306) is accessible. This should only listen on localhost.",
           "steps":["Edit /etc/mysql/mysql.conf.d/mysqld.cnf","Set: bind-address = 127.0.0.1","Restart MySQL","Block externally with firewall"],
           "cmd_win":"netsh advfirewall firewall add rule name=\"Block MySQL\" dir=in action=block protocol=TCP localport=3306",
           "cmd_linux":"sudo ufw deny 3306"},
    5432: {"id":"DB-002","title":"PostgreSQL Database Exposed","severity":"CRITICAL",
           "desc":"PostgreSQL (port 5432) is accessible externally.",
           "steps":["Edit postgresql.conf","Set listen_addresses = 'localhost'","Restart PostgreSQL"],
           "cmd_win":"netsh advfirewall firewall add rule name=\"Block PG\" dir=in action=block protocol=TCP localport=5432",
           "cmd_linux":"sudo ufw deny 5432"},
    6379: {"id":"DB-003","title":"Redis Exposed — CRITICAL","severity":"CRITICAL",
           "desc":"Redis has no authentication by default. Exposed Redis = full server compromise.",
           "steps":["Edit /etc/redis/redis.conf","Set bind 127.0.0.1","Set requirepass YourStrongPassword","Restart Redis"],
           "cmd_win":"netsh advfirewall firewall add rule name=\"Block Redis\" dir=in action=block protocol=TCP localport=6379",
           "cmd_linux":"sudo ufw deny 6379"},
    3389: {"id":"RDP-001","title":"RDP Remote Desktop Open","severity":"HIGH",
           "desc":"RDP allows remote control. Brute-force and BlueKeep attacks target this port.",
           "steps":["Enable Network Level Authentication (NLA)","Restrict to specific IPs only","Use VPN for remote access","Disable if unused"],
           "cmd_win":"netsh advfirewall firewall add rule name=\"Block RDP\" dir=in action=block protocol=TCP localport=3389",
           "cmd_linux":"sudo ufw deny 3389"},
    8080: {"id":"WEB-003","title":"Alt HTTP Server Running","severity":"MEDIUM",
           "desc":"Port 8080 is open. Often used by development servers — verify it should be public.",
           "steps":["Confirm this is intentional","If development, bind to 127.0.0.1 only","Apply same HTTPS hardening as port 80"],
           "cmd_win":"netsh advfirewall firewall add rule name=\"Block 8080\" dir=in action=block protocol=TCP localport=8080",
           "cmd_linux":"sudo ufw deny 8080"},
}


def _check_admin():
    """Check if running as admin/root."""
    try:
        if OS == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def _check_firewall():
    """Check if system firewall is active."""
    try:
        if OS == "Windows":
            r = subprocess.run(["netsh","advfirewall","show","allprofiles","state"],
                               capture_output=True, text=True, timeout=5)
            return "ON" in r.stdout.upper()
        else:
            r = subprocess.run(["ufw","status"], capture_output=True, text=True, timeout=5)
            return "active" in r.stdout.lower()
    except Exception:
        return None


def _check_auto_update():
    """Check if auto-updates are configured."""
    try:
        if OS == "Linux":
            return os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades")
        return None
    except Exception:
        return None


def _check_world_writable():
    """Find world-writable files in common dirs (Linux)."""
    if OS != "Linux":
        return []
    found = []
    try:
        r = subprocess.run(
            ["find", "/etc", "-maxdepth", "2", "-perm", "-o+w", "-type", "f"],
            capture_output=True, text=True, timeout=5)
        found = [l for l in r.stdout.strip().splitlines() if l][:5]
    except Exception:
        pass
    return found


def _check_failed_logins():
    """Count recent failed logins (Linux only)."""
    try:
        if OS == "Linux":
            r = subprocess.run(["grep", "-c", "Failed password", "/var/log/auth.log"],
                               capture_output=True, text=True, timeout=3)
            return int(r.stdout.strip()) if r.returncode == 0 else 0
    except Exception:
        pass
    return 0


def run_all_checks():
    findings = []

    # 1. Open port vulnerabilities
    open_ports = scan_local_ports()
    for pinfo in open_ports:
        port = pinfo["port"]
        if port in VULN_DB:
            v = VULN_DB[port].copy()
            v.update({"port": port, "severity": pinfo["severity"], "status": "OPEN", "type": "port"})
            findings.append(v)

    # 2. Admin / root privilege check
    is_admin = _check_admin()
    if is_admin:
        findings.append({
            "id": "PRIV-001", "title": "Running as Administrator / Root",
            "desc": f"CyberAI is running with elevated privileges on {OS}. Use a dedicated low-privilege service account.",
            "severity": "HIGH", "status": "DETECTED", "type": "privilege",
            "steps": ["Create a dedicated service user","Grant only required permissions","Restart CyberAI under that account"],
            "cmd_win": "net user cyberai_svc /add && net localgroup Users cyberai_svc /add",
            "cmd_linux": "sudo useradd -r -s /bin/false cyberai_svc"
        })

    # 3. Firewall status
    fw = _check_firewall()
    if fw is False:
        findings.append({
            "id": "FW-001", "title": "System Firewall is DISABLED",
            "desc": "The OS firewall (Windows Firewall / ufw) is not active. Enable it immediately.",
            "severity": "CRITICAL", "status": "DETECTED", "type": "firewall",
            "steps": ["Enable the firewall","Configure allow rules for needed services only","Block all inbound by default"],
            "cmd_win": "netsh advfirewall set allprofiles state on",
            "cmd_linux": "sudo ufw enable && sudo ufw default deny incoming"
        })
    elif fw is True:
        findings.append({
            "id": "FW-OK", "title": "System Firewall is Active",
            "desc": "Your OS firewall is enabled. Review rules periodically to remove stale entries.",
            "severity": "LOW", "status": "OK", "type": "firewall",
            "steps": ["Review firewall rules regularly","Remove unused allow rules"],
            "cmd_win": "netsh advfirewall firewall show rule name=all",
            "cmd_linux": "sudo ufw status verbose"
        })

    # 4. Auto-updates (Linux)
    auto_upd = _check_auto_update()
    if auto_upd is False:
        findings.append({
            "id": "UPD-001", "title": "Automatic Security Updates Disabled",
            "desc": "Unattended-upgrades not configured. Unpatched systems are primary attack targets.",
            "severity": "HIGH", "status": "DETECTED", "type": "update",
            "steps": ["Install unattended-upgrades","Configure /etc/apt/apt.conf.d/20auto-upgrades","Enable security-only updates"],
            "cmd_win": "", "cmd_linux": "sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades"
        })

    # 5. World-writable files (Linux)
    ww = _check_world_writable()
    if ww:
        findings.append({
            "id": "PERM-001", "title": f"World-Writable Files Found ({len(ww)})",
            "desc": f"Files in /etc are writable by all users: {', '.join(ww[:3])}. Any user can modify system config.",
            "severity": "HIGH", "status": "DETECTED", "type": "permissions",
            "steps": [f"Run: chmod o-w {f}" for f in ww[:3]] + ["Audit all /etc permissions"],
            "cmd_win": "", "cmd_linux": f"sudo chmod o-w {' '.join(ww[:3])}"
        })

    # 6. Failed login count
    fl = _check_failed_logins()
    if fl > 50:
        findings.append({
            "id": "AUTH-001", "title": f"High Failed Login Count ({fl})",
            "desc": f"{fl} failed SSH login attempts found in /var/log/auth.log. Consider installing fail2ban.",
            "severity": "HIGH" if fl > 200 else "MEDIUM", "status": "DETECTED", "type": "auth",
            "steps": ["Install fail2ban","Configure maxretry=5 bantime=3600","Monitor /var/log/auth.log"],
            "cmd_win": "", "cmd_linux": "sudo apt install fail2ban && sudo systemctl enable fail2ban"
        })

    # 7. Password policy (always included)
    findings.append({
        "id": "PASS-001", "title": "Password Policy Review",
        "desc": "Verify all accounts enforce strong passwords, 2FA, and account lockout.",
        "severity": "MEDIUM", "status": "CHECK_NEEDED", "type": "policy",
        "steps": ["Enable complexity requirements","Set minimum length: 12+ chars",
                  "Enable account lockout after 5 failed attempts","Enable 2FA on all accounts",
                  "Audit accounts with no password: sudo passwd -S -a | grep NP"],
        "cmd_win": "net accounts /minpwlen:12 /lockoutthreshold:5",
        "cmd_linux": "sudo passwd -e $(whoami)"
    })

    return findings


def get_summary(findings):
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        c[sev] = c.get(sev, 0) + 1
    return {"total": len(findings), "by_severity": c}