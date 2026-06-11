# utils/alerts.py - Email and Telegram Alerts
import smtplib
import requests
import json
import os
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from collections import deque

# Alert configuration
ALERT_CONFIG = {
    "email_enabled": os.environ.get("ALERT_EMAIL_ENABLED", "false").lower() == "true",
    "email_smtp_server": os.environ.get("ALERT_SMTP_SERVER", "smtp.gmail.com"),
    "email_smtp_port": int(os.environ.get("ALERT_SMTP_PORT", "587")),
    "email_username": os.environ.get("ALERT_EMAIL_USER", ""),
    "email_password": os.environ.get("ALERT_EMAIL_PASS", ""),
    "email_recipients": os.environ.get("ALERT_EMAIL_RECIPIENTS", "").split(","),
    
    "telegram_enabled": os.environ.get("ALERT_TELEGRAM_ENABLED", "false").lower() == "true",
    "telegram_bot_token": os.environ.get("TELEGRAM_BOT_TOKEN", ""),
    "telegram_chat_id": os.environ.get("TELEGRAM_CHAT_ID", ""),
    
    "webhook_enabled": os.environ.get("ALERT_WEBHOOK_ENABLED", "false").lower() == "true",
    "webhook_url": os.environ.get("ALERT_WEBHOOK_URL", ""),
}

# Alert deduplication
_sent_alerts = deque(maxlen=100)  # Store last 100 alert IDs

def _should_send_alert(alert_id, cooldown_seconds=300):
    """Check if alert should be sent (deduplication)"""
    now = time.time()
    for alert in _sent_alerts:
        if alert["id"] == alert_id and now - alert["timestamp"] < cooldown_seconds:
            return False
    return True

def _record_alert(alert_id):
    """Record that an alert was sent"""
    _sent_alerts.append({"id": alert_id, "timestamp": time.time()})

def send_email_alert(subject, body, is_html=False):
    """Send email alert"""
    if not ALERT_CONFIG["email_enabled"]:
        return {"success": False, "error": "Email alerts disabled"}
    
    try:
        msg = MIMEMultipart()
        msg["From"] = ALERT_CONFIG["email_username"]
        msg["To"] = ", ".join(ALERT_CONFIG["email_recipients"])
        msg["Subject"] = f"[CyberAI Alert] {subject}"
        
        if is_html:
            msg.attach(MIMEText(body, "html"))
        else:
            msg.attach(MIMEText(body, "plain"))
        
        server = smtplib.SMTP(ALERT_CONFIG["email_smtp_server"], ALERT_CONFIG["email_smtp_port"])
        server.starttls()
        server.login(ALERT_CONFIG["email_username"], ALERT_CONFIG["email_password"])
        server.send_message(msg)
        server.quit()
        
        return {"success": True, "message": "Email sent"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def send_telegram_alert(message):
    """Send Telegram alert"""
    if not ALERT_CONFIG["telegram_enabled"]:
        return {"success": False, "error": "Telegram alerts disabled"}
    
    try:
        url = f"https://api.telegram.org/bot{ALERT_CONFIG['telegram_bot_token']}/sendMessage"
        payload = {
            "chat_id": ALERT_CONFIG["telegram_chat_id"],
            "text": f"🚨 *CyberAI Alert* 🚨\n\n{message}",
            "parse_mode": "Markdown"
        }
        response = requests.post(url, json=payload, timeout=10)
        
        if response.status_code == 200:
            return {"success": True, "message": "Telegram alert sent"}
        else:
            return {"success": False, "error": f"Telegram API error: {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def send_webhook_alert(data):
    """Send webhook alert"""
    if not ALERT_CONFIG["webhook_enabled"]:
        return {"success": False, "error": "Webhook alerts disabled"}
    
    try:
        response = requests.post(
            ALERT_CONFIG["webhook_url"],
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code in [200, 201, 202]:
            return {"success": True, "message": "Webhook sent"}
        else:
            return {"success": False, "error": f"Webhook error: {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def send_critical_alert(alert_data):
    """Send critical alert through all configured channels"""
    alert_id = f"{alert_data.get('level', 'UNKNOWN')}_{alert_data.get('timestamp', time.time())}"
    
    if not _should_send_alert(alert_id, cooldown_seconds=300):
        return {"success": False, "error": "Alert already sent recently"}
    
    # Format message
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level = alert_data.get("level", "UNKNOWN")
    risk = alert_data.get("risk", 0)
    reasons = "\n".join(alert_data.get("reasons", [])[:5])
    ips = ", ".join(alert_data.get("ips", []))
    
    message = f"""
**Level:** {level}
**Risk:** {risk}%
**Time:** {timestamp}
**Reasons:** 
{reasons}
**Threat IPs:** {ips or "None detected"}
**Action:** {alert_data.get('action', 'MONITOR')}
    """
    
    # HTML version for email
    html_message = f"""
    <html>
    <body>
        <h2 style="color: {'#dc2626' if level == 'CRITICAL' else '#f97316'}">🚨 CyberAI Critical Alert</h2>
        <table border="0" cellpadding="8" style="border-collapse: collapse;">
            <tr><td><strong>Level:</strong></td><td style="color: {'#dc2626' if level == 'CRITICAL' else '#f97316'}">{level}</td></tr>
            <tr><td><strong>Risk:</strong></td><td>{risk}%</td></tr>
            <tr><td><strong>Time:</strong></td><td>{timestamp}</td></tr>
            <tr><td><strong>Action:</strong></td><td>{alert_data.get('action', 'MONITOR')}</td></tr>
            <tr><td valign="top"><strong>Reasons:</strong></td><td><ul>{"".join(f"<li>{r}</li>" for r in alert_data.get('reasons', [])[:5])}</ul></td></tr>
            <tr><td valign="top"><strong>Threat IPs:</strong></td><td>{ips or "None detected"}</td></tr>
        </table>
        <p><a href="http://localhost:5000">View Dashboard →</a></p>
    </body>
    </html>
    """
    
    results = []
    
    # Send email for CRITICAL or HIGH alerts
    if level in ["CRITICAL", "HIGH"]:
        email_result = send_email_alert(f"{level} Security Alert - Risk {risk}%", html_message, is_html=True)
        results.append(email_result)
    
    # Send Telegram for CRITICAL only
    if level == "CRITICAL":
        telegram_result = send_telegram_alert(message)
        results.append(telegram_result)
    
    # Send webhook if configured
    if ALERT_CONFIG["webhook_enabled"]:
        webhook_result = send_webhook_alert(alert_data)
        results.append(webhook_result)
    
    _record_alert(alert_id)
    
    return {
        "success": any(r.get("success", False) for r in results),
        "results": results,
        "alert_id": alert_id
    }

# ==================== Alert Sound ====================

def generate_alert_sound_js():
    """Generate JavaScript for browser alert sounds"""
    return """
    // Alert Sound Generator
    let audioContext = null;
    let isAudioEnabled = false;
    
    function initAudio() {
        if (!audioContext) {
            audioContext = new (window.AudioContext || window.webkitAudioContext)();
        }
        isAudioEnabled = true;
        console.log("Audio initialized");
    }
    
    function playAlertSound(level) {
        if (!isAudioEnabled && level === 'CRITICAL') {
            // Auto-initialize on first CRITICAL alert
            initAudio();
        }
        if (!isAudioEnabled) return;
        
        const now = audioContext.currentTime;
        const gain = audioContext.createGain();
        gain.connect(audioContext.destination);
        
        if (level === 'CRITICAL') {
            // Siren sound for CRITICAL
            const oscillator = audioContext.createOscillator();
            oscillator.type = 'sawtooth';
            oscillator.connect(gain);
            
            // Frequency sweep
            oscillator.frequency.setValueAtTime(800, now);
            oscillator.frequency.exponentialRampToValueAtTime(400, now + 0.2);
            oscillator.frequency.exponentialRampToValueAtTime(800, now + 0.4);
            oscillator.frequency.exponentialRampToValueAtTime(400, now + 0.6);
            
            gain.gain.setValueAtTime(0.3, now);
            gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.8);
            
            oscillator.start();
            oscillator.stop(now + 0.8);
        } else if (level === 'HIGH') {
            // Two beeps for HIGH
            const oscillator1 = audioContext.createOscillator();
            oscillator1.type = 'sine';
            oscillator1.frequency.value = 880;
            oscillator1.connect(gain);
            gain.gain.setValueAtTime(0.2, now);
            gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.15);
            oscillator1.start();
            oscillator1.stop(now + 0.15);
            
            setTimeout(() => {
                const oscillator2 = audioContext.createOscillator();
                oscillator2.type = 'sine';
                oscillator2.frequency.value = 880;
                oscillator2.connect(gain);
                gain.gain.setValueAtTime(0.2, now + 0.3);
                gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.45);
                oscillator2.start();
                oscillator2.stop(now + 0.45);
            }, 300);
        } else if (level === 'MEDIUM') {
            // Single beep for MEDIUM
            const oscillator = audioContext.createOscillator();
            oscillator.type = 'sine';
            oscillator.frequency.value = 660;
            oscillator.connect(gain);
            gain.gain.setValueAtTime(0.15, now);
            gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.2);
            oscillator.start();
            oscillator.stop(now + 0.2);
        }
    }
    
    function playTestSound() {
        if (!audioContext) initAudio();
        const oscillator = audioContext.createOscillator();
        const gain = audioContext.createGain();
        oscillator.connect(gain);
        gain.connect(audioContext.destination);
        oscillator.frequency.value = 440;
        gain.gain.setValueAtTime(0.2, audioContext.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, audioContext.currentTime + 0.5);
        oscillator.start();
        oscillator.stop(audioContext.currentTime + 0.5);
    }
    
    function enableAudio() {
        initAudio();
        alert("🔊 Audio alerts enabled");
    }
    
    // Request notification permission
    if ("Notification" in window) {
        Notification.requestPermission();
    }
    
    function showBrowserNotification(title, body, level) {
        if (Notification.permission === "granted") {
            const icon = level === "CRITICAL" ? "🔴" : level === "HIGH" ? "🟠" : "🟡";
            new Notification(`[${level}] ${title}`, {
                body: body,
                icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23dc2626'%3E%3Cpath d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z'/%3E%3C/svg%3E",
                silent: false
            });
        }
    }
    
    // Expose functions globally
    window.playAlertSound = playAlertSound;
    window.enableAudio = enableAudio;
    window.playTestSound = playTestSound;
    window.showBrowserNotification = showBrowserNotification;
    """