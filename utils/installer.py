# installer.py - One-click installation script
#!/usr/bin/env python3
"""
CyberAI Installer - One-click installation and setup
Run: python installer.py
"""

import os
import sys
import subprocess
import platform
import shutil
import json
import stat
import getpass
from pathlib import Path

INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
SYSTEM = platform.system()

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.OKCYAN}
╔══════════════════════════════════════════════════════════════╗
║                    CYBER AI INSTALLER                         ║
║              Autonomous Cyber Defense Platform                ║
╚══════════════════════════════════════════════════════════════╝
{Colors.ENDC}
    """
    print(banner)

def run_command(cmd, description=None):
    """Run a command and print output"""
    if description:
        print(f"{Colors.OKBLUE}▶ {description}...{Colors.ENDC}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"{Colors.OKGREEN}✓ Success{Colors.ENDC}")
            return True, result.stdout
        else:
            print(f"{Colors.FAIL}✗ Failed: {result.stderr}{Colors.ENDC}")
            return False, result.stderr
    except Exception as e:
        print(f"{Colors.FAIL}✗ Error: {e}{Colors.ENDC}")
        return False, str(e)

def check_python():
    """Check Python version"""
    print(f"{Colors.OKBLUE}▶ Checking Python version...{Colors.ENDC}")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 7:
        print(f"{Colors.OKGREEN}✓ Python {version.major}.{version.minor}.{version.micro} detected{Colors.ENDC}")
        return True
    else:
        print(f"{Colors.FAIL}✗ Python 3.7+ required (found {version.major}.{version.minor}){Colors.ENDC}")
        return False

def install_dependencies():
    """Install Python dependencies"""
    print(f"{Colors.OKBLUE}▶ Installing Python dependencies...{Colors.ENDC}")
    
    requirements = [
        "flask",
        "flask-cors",
        "colorama",
        "psutil",
        "scikit-learn",
        "networkx",
        "numpy",
        "cryptography",
        "pyopenssl",
        "requests",
        "reportlab",
        "pytz",
        "python-dateutil",
    ]
    
    for pkg in requirements:
        success, _ = run_command(f"{sys.executable} -m pip install {pkg}", f"  Installing {pkg}")
        if not success:
            print(f"{Colors.WARNING}⚠ Failed to install {pkg}, continuing...{Colors.ENDC}")
    
    print(f"{Colors.OKGREEN}✓ Dependencies installed{Colors.ENDC}")
    return True

def create_virtual_env():
    """Create virtual environment (optional)"""
    response = input(f"{Colors.OKCYAN}Create virtual environment? (y/n) [n]: {Colors.ENDC}").strip().lower()
    if response == 'y':
        venv_path = os.path.join(INSTALL_DIR, "venv")
        success, _ = run_command(f"{sys.executable} -m venv {venv_path}", "Creating virtual environment")
        if success:
            if SYSTEM == "Windows":
                pip_path = os.path.join(venv_path, "Scripts", "pip")
                python_path = os.path.join(venv_path, "Scripts", "python")
            else:
                pip_path = os.path.join(venv_path, "bin", "pip")
                python_path = os.path.join(venv_path, "bin", "python")
            
            run_command(f"{pip_path} install -r requirements.txt", "Installing packages in venv")
            print(f"{Colors.OKGREEN}✓ Virtual environment created at {venv_path}{Colors.ENDC}")
            print(f"  Activate with: source {venv_path}/bin/activate (Linux/Mac) or {venv_path}\\Scripts\\activate (Windows)")
            return venv_path
    return None

def configure_api_keys():
    """Configure API keys for threat intelligence"""
    config_file = os.path.join(INSTALL_DIR, "config.json")
    
    if os.path.exists(config_file):
        response = input(f"{Colors.OKCYAN}API keys already configured. Reconfigure? (y/n) [n]: {Colors.ENDC}").strip().lower()
        if response != 'y':
            return
    
    print(f"{Colors.OKCYAN}\n📡 Threat Intelligence API Configuration{Colors.ENDC}")
    print("Get free API keys at:")
    print("  - VirusTotal: https://www.virustotal.com/gui/join-us")
    print("  - AbuseIPDB: https://www.abuseipdb.com/register")
    print("  - Shodan: https://account.shodan.io/register")
    print("  - AlienVault OTX: https://otx.alienvault.com/api")
    print()
    
    config = {
        "virustotal_api_key": input("VirusTotal API Key (optional): ").strip(),
        "abuseipdb_api_key": input("AbuseIPDB API Key (optional): ").strip(),
        "shodan_api_key": input("Shodan API Key (optional): ").strip(),
        "alienvault_api_key": input("AlienVault OTX API Key (optional): ").strip(),
        "alert_email_enabled": "false",
        "alert_telegram_enabled": "false",
        "alert_webhook_enabled": "false",
    }
    
    # Email alerts
    if input(f"{Colors.OKCYAN}Configure email alerts? (y/n) [n]: {Colors.ENDC}").strip().lower() == 'y':
        config["alert_email_enabled"] = "true"
        config["alert_smtp_server"] = input("SMTP Server (e.g., smtp.gmail.com): ").strip()
        config["alert_smtp_port"] = input("SMTP Port (587): ").strip() or "587"
        config["alert_email_user"] = input("Email Username: ").strip()
        config["alert_email_pass"] = getpass.getpass("Email Password: ")
        config["alert_email_recipients"] = input("Recipient Email(s) (comma-separated): ").strip()
    
    # Telegram alerts
    if input(f"{Colors.OKCYAN}Configure Telegram alerts? (y/n) [n]: {Colors.ENDC}").strip().lower() == 'y':
        config["alert_telegram_enabled"] = "true"
        config["telegram_bot_token"] = input("Telegram Bot Token: ").strip()
        config["telegram_chat_id"] = input("Telegram Chat ID: ").strip()
    
    # Webhook alerts
    if input(f"{Colors.OKCYAN}Configure webhook alerts? (y/n) [n]: {Colors.ENDC}").strip().lower() == 'y':
        config["alert_webhook_enabled"] = "true"
        config["webhook_url"] = input("Webhook URL: ").strip()
    
    # Save config
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"{Colors.OKGREEN}✓ API keys saved to {config_file}{Colors.ENDC}")

def create_startup_script():
    """Create startup scripts for different platforms"""
    if SYSTEM == "Windows":
        script_content = f"""@echo off
cd /d {INSTALL_DIR}
python run_all.py
pause
"""
        script_path = os.path.join(INSTALL_DIR, "start_cyberai.bat")
        with open(script_path, 'w') as f:
            f.write(script_content)
        print(f"{Colors.OKGREEN}✓ Created startup script: start_cyberai.bat{Colors.ENDC}")
    
    elif SYSTEM == "Linux" or SYSTEM == "Darwin":
        script_content = f"""#!/bin/bash
cd {INSTALL_DIR}
python3 run_all.py
"""
        script_path = os.path.join(INSTALL_DIR, "start_cyberai.sh")
        with open(script_path, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"{Colors.OKGREEN}✓ Created startup script: start_cyberai.sh (chmod +x){Colors.ENDC}")

def create_systemd_service():
    """Create systemd service for Linux"""
    if SYSTEM != "Linux":
        return
    
    response = input(f"{Colors.OKCYAN}Create systemd service for auto-start? (y/n) [n]: {Colors.ENDC}").strip().lower()
    if response != 'y':
        return
    
    service_content = f"""[Unit]
Description=CyberAI Security Platform
After=network.target

[Service]
Type=simple
User={os.environ.get('USER', 'root')}
WorkingDirectory={INSTALL_DIR}
ExecStart={sys.executable} {os.path.join(INSTALL_DIR, 'run_all.py')}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    service_path = f"/etc/systemd/system/cyberai.service"
    try:
        with open(service_path, 'w') as f:
            f.write(service_content)
        run_command("sudo systemctl daemon-reload", "Reloading systemd")
        run_command("sudo systemctl enable cyberai", "Enabling service")
        print(f"{Colors.OKGREEN}✓ Created systemd service: cyberai.service{Colors.ENDC}")
        print("  Start with: sudo systemctl start cyberai")
        print("  Check status: sudo systemctl status cyberai")
    except Exception as e:
        print(f"{Colors.FAIL}✗ Failed to create service: {e}{Colors.ENDC}")

def create_dockerfile():
    """Create Dockerfile for containerized deployment"""
    dockerfile_content = f"""FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    tcpdump \\
    nmap \\
    net-tools \\
    iproute2 \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directories
RUN mkdir -p backups data

# Expose dashboard port
EXPOSE 5000

# Run the application
CMD ["python", "run_all.py"]
"""
    dockerfile_path = os.path.join(INSTALL_DIR, "Dockerfile")
    with open(dockerfile_path, 'w') as f:
        f.write(dockerfile_content)
    
    # Create .dockerignore
    dockerignore_content = """__pycache__
*.pyc
*.pyo
*.pyd
.Python
*.so
*.egg
*.egg-info
dist
build
venv
env
.env
.git
.gitignore
*.log
*.db
*.sqlite
*.sqlite3
backups/
.DS_Store
"""
    dockerignore_path = os.path.join(INSTALL_DIR, ".dockerignore")
    with open(dockerignore_path, 'w') as f:
        f.write(dockerignore_content)
    
    print(f"{Colors.OKGREEN}✓ Created Dockerfile and .dockerignore{Colors.ENDC}")
    print("  Build: docker build -t cyberai .")
    print("  Run: docker run -p 5000:5000 cyberai")

def setup_firewall_rules():
    """Setup firewall rules for the application"""
    print(f"{Colors.OKBLUE}▶ Setting up firewall rules...{Colors.ENDC}")
    
    if SYSTEM == "Windows":
        # Add firewall rule for dashboard
        success, _ = run_command(
            f'netsh advfirewall firewall add rule name="CyberAI Dashboard" dir=in action=allow protocol=TCP localport=5000',
            "Adding firewall rule for dashboard port 5000"
        )
    
    elif SYSTEM == "Linux":
        # Check if ufw is available
        success, _ = run_command("which ufw", "Checking ufw")
        if success:
            response = input(f"{Colors.OKCYAN}Allow port 5000 through ufw? (y/n) [n]: {Colors.ENDC}").strip().lower()
            if response == 'y':
                run_command("sudo ufw allow 5000/tcp", "Adding ufw rule for port 5000")
                run_command("sudo ufw reload", "Reloading ufw")

def main():
    print_banner()
    
    print(f"{Colors.BOLD}Installation Directory: {INSTALL_DIR}{Colors.ENDC}\n")
    
    # Check prerequisites
    if not check_python():
        sys.exit(1)
    
    # Create virtual environment (optional)
    venv_path = create_virtual_env()
    
    # Install dependencies
    install_dependencies()
    
    # Configure API keys
    configure_api_keys()
    
    # Setup firewall
    setup_firewall_rules()
    
    # Create startup scripts
    create_startup_script()
    
    # Create systemd service (Linux)
    create_systemd_service()
    
    # Create Dockerfile
    create_dockerfile()
    
    # Create data directories
    os.makedirs(os.path.join(INSTALL_DIR, "backups"), exist_ok=True)
    os.makedirs(os.path.join(INSTALL_DIR, "data"), exist_ok=True)
    
    print(f"\n{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}Installation Complete!{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}\n")
    
    print(f"{Colors.BOLD}To start CyberAI:{Colors.ENDC}")
    if SYSTEM == "Windows":
        print(f"  Double-click: {os.path.join(INSTALL_DIR, 'start_cyberai.bat')}")
    else:
        print(f"  Run: python {os.path.join(INSTALL_DIR, 'run_all.py')}")
        print(f"  Or: ./{os.path.join(INSTALL_DIR, 'start_cyberai.sh')}")
    
    print(f"\n{Colors.BOLD}Dashboard:{Colors.ENDC}")
    print(f"  http://localhost:5000")
    print(f"  Username: yashwanth")
    print(f"  Password: CyberAI2024")
    
    print(f"\n{Colors.BOLD}Next Steps:{Colors.ENDC}")
    print(f"  1. Open dashboard and run Security Advisor")
    print(f"  2. Configure API keys in config.json for threat intel")
    print(f"  3. Run Attack Simulation to test detection")
    print(f"  4. Check System Status for resource usage")
    
    # Ask to run now
    response = input(f"\n{Colors.OKCYAN}Start CyberAI now? (y/n) [y]: {Colors.ENDC}").strip().lower()
    if response != 'n':
        if SYSTEM == "Windows":
            os.system(f"start {os.path.join(INSTALL_DIR, 'start_cyberai.bat')}")
        else:
            os.system(f"python {os.path.join(INSTALL_DIR, 'run_all.py')} &")
        print(f"{Colors.OKGREEN}CyberAI started in background!{Colors.ENDC}")

if __name__ == "__main__":
    main()