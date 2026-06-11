# utils/response.py
MESSAGES = {
    "BLOCK_IP":        "🌐 Blocking IP via firewall",
    "BLOCK_USER":      "🚫 Blocking user account",
    "BLOCK_NETWORK":   "🚨 Blocking network traffic",
    "ISOLATE_SYSTEM":  "🛑 Isolating system",
    "STOP_RANSOMWARE": "☣️  Stopping ransomware",
    "KILL_PROCESS":    "⚙️  Killing suspicious process",
    "MONITOR":         "👁️  Monitoring",
    "ALLOW":           "✅ System normal",
    "SECURE_DATABASE": "🗄️  Securing database",
}
def execute_action(action):
    msg = MESSAGES.get(action, f"🔧 {action}")
    print(f"  {msg}")
    return msg
