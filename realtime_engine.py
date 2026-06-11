# realtime_engine.py — CyberAI Real-Time Monitoring Engine (FULL WORKING VERSION)
import time
import platform
import collections
from datetime import datetime
from colorama import Fore, Style, init as colorama_init

from graph.graph_engine import SecurityGraph
from core.orchestrator import Orchestrator
from utils.memory import store_attack, memory_db
from utils.response import execute_action
from utils.scanner import get_vulnerabilities

from monitor.process_monitor import ProcessMonitor
from monitor.network_monitor import NetworkMonitor

if platform.system() == "Windows":
    from monitor.windows_monitor import WindowsMonitor as OSMonitor
else:
    from monitor.linux_monitor import LinuxMonitor as OSMonitor

MITRE_OK = False
try:
    from mitre.tactical_engine import load_all_detectors, run_all_detectors, get_coverage_summary
    MITRE_OK = True
except ImportError as e:
    print(f"  [MITRE] Not loaded: {e}")

ADVANCED_OK = False
try:
    from advanced.advanced_engine import load_advanced_detectors, run_advanced_detectors, get_advanced_status
    ADVANCED_OK = True
except ImportError as e:
    print(f"  [Advanced] Not loaded: {e}")

PREVENTION_OK = False
try:
    from prevention.engine import propose_prevention
    PREVENTION_OK = True
except ImportError as e:
    print(f"  [Prevention] Not loaded: {e}")

SECURITY_OK = False
try:
    from security.data_security import init_security, check_integrity, create_backup
    SECURITY_OK = True
except ImportError:
    pass

colorama_init(autoreset=True)

shared_state = {
    "alerts": collections.deque(maxlen=200),
    "event_timeline": collections.deque(maxlen=20),
    "top_ips": collections.defaultdict(int),
    "mitre_hits": collections.defaultdict(int),
    "current_risk": 0,
    "current_level": "LOW",
    "total_events": 0,
    "total_alerts": 0,
    "poll_count": 0,
    "start_time": time.time(),
    "system_status": "STARTING",
    "mitre_coverage": {},
    "advanced_status": {},
    "pending_count": 0,
}

POLL_INTERVAL = 5

def _update_graph(graph, events):
    for ev in events:
        t = ev.get("type", "")
        ip = ev.get("ip", "local")
        u = ev.get("username", "unknown")
        if t == "fail_login":
            graph.add_event(ip, u, "brute_force")
            graph.add_event(u, "system", "login_attempt")
        elif t == "login_success":
            graph.add_event(ip, u, "authenticated")
            graph.add_event(u, "system", "accessed")
        elif t == "admin_access":
            graph.add_event(u, "admin_context", "escalated")
            graph.add_event(ip, "critical_system", "admin_access")
        elif t in ("process_create", "suspicious_process"):
            proc = ev.get("process", "unknown")
            graph.add_event(u, proc, "executed")
            graph.add_event(proc, "system", "running")
        elif t == "port_connect":
            graph.add_event(ip, "local_service", "connected")
        elif t == "mitre_detection":
            graph.add_event(ip, f"MITRE_{ev.get('technique_id','?')}", "detected")

def _build_feature(events):
    fails = sum(1 for e in events if e.get("type") == "fail_login")
    admins = sum(1 for e in events if e.get("type") == "admin_access")
    procs = sum(1 for e in events if e.get("type") in ("process_create", "suspicious_process"))
    nets = sum(1 for e in events if e.get("type") == "port_connect")
    mitre = sum(1 for e in events if e.get("type") == "mitre_detection")
    ips = len({e.get("ip", "") for e in events if e.get("ip", "") not in ("", "local", "unknown", "127.0.0.1", "::1")})
    return [fails + admins * 2 + procs * 2 + nets + mitre * 3 + ips]
# In realtime_engine.py, after collecting network events, add protocol info:
def _extract_protocols(events):
    """Extract network protocols from events for OSI model."""
    protocols = set()
    
    for ev in events:
        ev_type = ev.get("type", "")
        
        # Process port connections
        if ev_type == "port_connect":
            port = ev.get("port", 0)
            protocol = ev.get("protocol", "").lower()
            
            if protocol:
                protocols.add(protocol)
            
            # Port-based protocol detection
            port_map = {
                21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
                53: "dns", 80: "http", 110: "pop3", 143: "imap",
                443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
                1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
                6379: "redis", 8080: "http", 8443: "https", 27017: "mongodb"
            }
            
            if port in port_map:
                proto = port_map[port]
                protocols.add(proto)
                if proto == "https":
                    protocols.add("tls")
            
            # Add transport protocol
            if ev.get("transport", "").lower() in ["tcp", "udp"]:
                protocols.add(ev["transport"].lower())
            else:
                protocols.add("tcp")  # Assume TCP for most port connections
        
        # Process MITRE detections
        elif ev_type == "mitre_detection":
            tid = ev.get("technique_id", "")
            if tid == "T1046":  # Network Service Scanning
                protocols.update(["tcp", "udp", "icmp", "ipv4"])
            elif tid == "T1071":  # C2 Beaconing
                protocols.update(["http", "https", "dns", "tcp"])
            elif tid == "T1021":  # Lateral Movement
                protocols.update(["smb", "rdp", "ssh", "tcp"])
            elif tid == "T1566":  # Phishing
                protocols.update(["smtp", "http", "https"])
            elif tid == "T1041":  # Exfiltration
                protocols.update(["http", "https", "dns", "ftp"])
        
        # Process network connections
        elif ev_type == "network_connection":
            proto = ev.get("protocol", "").lower()
            if proto:
                protocols.add(proto)
        
        # Check for IP addresses (indicates IPv4)
        if ev.get("ip") and ev.get("ip") not in ("local", "unknown", "127.0.0.1", "::1"):
            if ":" in ev["ip"]:
                protocols.add("ipv6")
            else:
                protocols.add("ipv4")
        
        # Check process command lines for network tools
        cmdline = ev.get("cmdline", "").lower()
        if cmdline:
            if "curl" in cmdline or "wget" in cmdline:
                protocols.update(["http", "https", "tcp", "dns"])
            if "ping" in cmdline:
                protocols.add("icmp")
            if "nslookup" in cmdline or "dig" in cmdline:
                protocols.add("dns")
            if "ssh" in cmdline:
                protocols.add("ssh")
            if "ftp" in cmdline:
                protocols.add("ftp")
    
    # Always include basic protocols if any network activity detected
    if protocols:
        protocols.add("tcp")
        protocols.add("ipv4")
    
    return list(protocols)



def _print_banner():
    print(Fore.CYAN + """
╔══════════════════════════════════════════════════════════╗
║         CYBER AI — REAL-TIME MONITORING ENGINE           ║
║         C. Yashwanth — Autonomous Cyber Defense AI       ║
╚══════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)
    print(f"  OS           : {platform.system()} {platform.release()}")
    print(f"  Poll every   : {POLL_INTERVAL} seconds")
    print(f"  Dashboard    : http://127.0.0.1:5000")
    print(f"  Prevention   : {'ON' if PREVENTION_OK else 'OFF'}")
    print(f"  MITRE Engine : {'ON' if MITRE_OK else 'OFF'}")
    print(f"  Advanced     : {'ON' if ADVANCED_OK else 'OFF'}")
    print(f"  Security     : {'ON' if SECURITY_OK else 'OFF'}")
    print(f"  Press        : Ctrl+C to stop\n")

def run():
    _print_banner()

    graph = SecurityGraph()
    orc = Orchestrator()
    os_mon = OSMonitor()
    proc_mon = ProcessMonitor()
    net_mon = NetworkMonitor()

    if MITRE_OK:
        load_all_detectors()

    if ADVANCED_OK:
        load_advanced_detectors()

    if SECURITY_OK:
        init_security()

    shared_state["system_status"] = "RUNNING"
    shared_state["start_time"] = time.time()

    print(f"  {Fore.GREEN}All systems initialised — monitoring started{Style.RESET_ALL}\n")

    poll_count = 0
    last_backup = time.time()
    last_summary = time.time()
    last_vuln = time.time()

    try:
        while True:
            poll_count += 1
            events = []

            try:
                events += os_mon.collect()
            except Exception:
                pass
            try:
                events += proc_mon.collect()
            except Exception:
                pass
            try:
                events += net_mon.collect()
            except Exception:
                pass

            if ADVANCED_OK and events:
                try:
                    events, adv_findings = run_advanced_detectors(events)
                    events += adv_findings
                except Exception:
                    pass

            if MITRE_OK and events:
                try:
                    mitre_findings = run_all_detectors(events)
                    events += mitre_findings
                except Exception:
                    pass

            shared_state["total_events"] += len(events)
            shared_state["poll_count"] = poll_count
            
            # Initialize timeline entry for this poll
            timeline_entry = {
                "poll": poll_count,
                "time": datetime.now().strftime("%H:%M:%S"),
                "events": len(events),
                "count": len(events),  # Add 'count' field for frontend compatibility
                "alerts": 0,
                "level": "LOW",
                "action": "monitor"
            }

            if events:
                _update_graph(graph, events)

                try:
                    feature = _build_feature(events)
                    result = orc.process(events, feature, 0, memory_db)
                    store_attack(result, events)

                    # --- Build alert from result ---
                    alert = {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "level": result.get("level", "LOW"),
                        "risk": int(result.get("risk", 0) * 100),
                        "reasons": result.get("reasons", []),
                        "mitre": list(set(
                            tid for r in result.get("reasons", [])
                            for tid in r.split() if tid.startswith("T")
                        )),
                        "action": result.get("action", "MONITOR"),
                        "ips": list({e.get("ip") for e in events if e.get("ip") and e.get("ip") not in ("local", "unknown", "127.0.0.1", "::1")})
                    }

                    # --- Update shared state with alert data ---
                    shared_state["alerts"].append(alert)
                    shared_state["total_alerts"] += 1
                    shared_state["current_risk"] = alert["risk"]
                    shared_state["current_level"] = alert["level"]

                    # --- Update top IPs ---
                    for ip in alert["ips"]:
                        shared_state["top_ips"][ip] += 1

                    # --- Update MITRE hits ---
                    for tid in alert["mitre"]:
                        shared_state["mitre_hits"][tid] += 1

                    # --- Update the timeline entry with alert info ---
                    timeline_entry["alerts"] = 1
                    timeline_entry["level"] = alert["level"]
                    timeline_entry["action"] = alert["action"]

                    print(f"  {Fore.YELLOW}[{alert['time']}] Alert: {alert['level']} ({alert['risk']}%){Style.RESET_ALL}")
                    
                except Exception as e:
                    print(f"  [Orchestrator error] {e}")

            # Add timeline entry (only once per poll)
            shared_state["event_timeline"].append(timeline_entry)

            print(f"\r  [{datetime.now().strftime('%H:%M:%S')}] Poll #{poll_count:04d} | Events: {len(events):3d}",
                  end="", flush=True)

            time.sleep(POLL_INTERVAL)
            shared_state["active_protocols"] = _extract_protocols(events)

            print(f"\r  [{datetime.now().strftime('%H:%M:%S')}] Poll #{poll_count:04d} | Events: {len(events):3d}",
                  end="", flush=True)

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}Monitoring stopped.{Style.RESET_ALL}")

if __name__ == "__main__":
    run()