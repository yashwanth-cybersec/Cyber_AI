# prevention/hardware_monitor.py
import socket
import time
import platform
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil
    OK = True
except ImportError:
    OK = False

OS = platform.system()

RISKY_PORTS  = {4444: "Metasploit", 1337: "Backdoor", 6667: "IRC/C2", 9001: "Tor"}
COMMON_PORTS = [21, 22, 23, 80, 443, 3306, 3389, 5432, 8080, 8443]

VENDOR_MAP = {
    # VMware / Virtual
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:15:5d": "Hyper-V",
    # Intel
    "00:1a:4b": "Intel", "00:1b:21": "Intel", "8c:8d:28": "Intel",
    # Apple (Mac/iPhone/iPad)
    "f4:5c:89": "Apple", "3c:22:fb": "Apple", "00:26:bb": "Apple",
    "18:65:90": "Apple", "ac:bc:32": "Apple", "f0:18:98": "Apple",
    "00:cd:fe": "Apple", "28:cf:e9": "Apple", "3c:15:c2": "Apple",
    "a4:83:e7": "Apple", "d8:bb:2c": "Apple", "70:73:cb": "Apple",
    "f8:27:93": "Apple", "b8:e8:56": "Apple", "34:ab:37": "Apple",
    "98:01:a7": "Apple", "e8:8d:28": "Apple", "cc:08:8d": "Apple",
    # Samsung (Android phones/tablets/TVs)
    "00:07:ab": "Samsung", "00:12:fb": "Samsung", "00:15:b9": "Samsung",
    "00:1d:25": "Samsung", "00:21:19": "Samsung", "10:d5:42": "Samsung",
    "2c:ae:2b": "Samsung", "34:23:ba": "Samsung", "40:0e:85": "Samsung",
    "50:32:75": "Samsung", "5c:0a:5b": "Samsung", "70:f9:27": "Samsung",
    "84:55:a5": "Samsung", "90:18:7c": "Samsung", "a0:0b:ba": "Samsung",
    "b4:79:a7": "Samsung", "c8:19:f7": "Samsung", "f4:42:8f": "Samsung",
    # Xiaomi / Redmi
    "00:9e:c8": "Xiaomi", "0c:1d:af": "Xiaomi", "10:2a:b3": "Xiaomi",
    "28:6c:07": "Xiaomi", "34:80:b3": "Xiaomi", "50:64:2b": "Xiaomi",
    "58:44:98": "Xiaomi", "64:09:80": "Xiaomi", "74:51:ba": "Xiaomi",
    "78:11:dc": "Xiaomi", "8c:be:be": "Xiaomi", "a4:50:46": "Xiaomi",
    "c4:0b:cb": "Xiaomi", "f8:a4:5f": "Xiaomi",
    # OnePlus
    "00:17:88": "Philips/OnePlus", "ac:37:43": "OnePlus", "94:65:2d": "OnePlus",
    # Google / Pixel / Nest
    "f4:f5:d8": "Google", "48:d6:d5": "Google", "1c:f2:9a": "Google",
    "a4:77:33": "Google", "54:60:09": "Google",
    # Huawei
    "00:18:82": "Huawei", "00:1e:10": "Huawei", "00:25:9e": "Huawei",
    "04:bd:70": "Huawei", "28:31:52": "Huawei", "40:4d:8e": "Huawei",
    "54:89:98": "Huawei", "70:72:3c": "Huawei", "84:74:2a": "Huawei",
    "a8:ca:7b": "Huawei", "d0:7a:b5": "Huawei", "e8:cd:2d": "Huawei",
    # Realme / OPPO / Vivo
    "00:1f:d0": "OPPO", "a8:9a:93": "OPPO", "4c:1a:3d": "Realme",
    "f4:8e:92": "Vivo", "38:a4:ed": "Vivo",
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    # TP-Link (routers)
    "00:1d:0f": "TP-Link", "14:cc:20": "TP-Link", "18:d6:c7": "TP-Link",
    "20:dc:e6": "TP-Link", "30:b5:c2": "TP-Link", "50:c7:bf": "TP-Link",
    "54:af:97": "TP-Link", "60:32:b1": "TP-Link", "70:4f:57": "TP-Link",
    "74:da:38": "TP-Link", "90:f6:52": "TP-Link", "a0:f3:c1": "TP-Link",
    "b0:95:75": "TP-Link", "c0:4a:00": "TP-Link", "d8:07:b6": "TP-Link",
    # Netgear (routers)
    "00:09:5b": "Netgear", "00:14:6c": "Netgear", "00:1b:2f": "Netgear",
    "20:4e:7f": "Netgear", "28:c6:8e": "Netgear", "84:1b:5e": "Netgear",
    # D-Link
    "00:05:5d": "D-Link", "00:17:9a": "D-Link", "00:1b:11": "D-Link",
    "1c:bd:b9": "D-Link", "28:10:7b": "D-Link", "34:08:04": "D-Link",
    # Amazon (Echo/Fire/Kindle)
    "40:b4:cd": "Amazon", "44:65:0d": "Amazon", "68:37:e9": "Amazon",
    "74:c2:46": "Amazon", "a0:02:dc": "Amazon", "b4:7c:9c": "Amazon",
    "f0:27:2d": "Amazon", "fc:a6:67": "Amazon",
}
def _get_local_interfaces():
    """Return list of (ip, netmask, iface) for all non-loopback IPv4 interfaces."""
    ifaces = []
    if not OK:
        return ifaces
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ifaces.append((addr.address, addr.netmask or "255.255.255.0", iface))
                print(f"  [Network] Found interface: {iface} -> {addr.address}")
    return ifaces
# ── Helpers ────────────────────────────────────────────────────────────

def scan_network_devices():
    """Scan local subnet and return list of discovered devices."""
    devices = []
    ifaces = _get_local_interfaces()
    
    # Debug output
    print(f"  [Network] Found {len(ifaces)} interfaces: {ifaces}")

    if not ifaces:
        # Fallback - get IP using a different method
        try:
            # Create a socket to get the actual local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Determine netmask
            if local_ip.startswith('192.168.'):
                netmask = "255.255.255.0"
            elif local_ip.startswith('10.'):
                netmask = "255.0.0.0"
            elif local_ip.startswith('172.'):
                netmask = "255.255.0.0"
            else:
                netmask = "255.255.255.0"
            
            hostname = socket.gethostname()
            devices.append({
                "ip": local_ip, 
                "hostname": hostname, 
                "mac": "—",
                "vendor": "—", 
                "type": "THIS PC", 
                "icon": "🖥️",
                "open_ports": _scan_ports(local_ip),
                "risk": "LOW", 
                "note": "Your machine", 
                "is_local": True,
            })
            
            # Add router/gateway
            gateway = '.'.join(local_ip.split('.')[:-1]) + '.1'
            devices.append({
                "ip": gateway,
                "hostname": "Router/Gateway",
                "mac": "—",
                "vendor": "Unknown",
                "type": "Wi-Fi Router",
                "icon": "🌐",
                "open_ports": [80, 443],
                "risk": "INFO",
                "note": "Your Wi-Fi router - check admin panel",
                "is_local": False,
            })
            
            print(f"  [Network] Fallback: Found {len(devices)} devices")
            return devices
            
        except Exception as e:
            print(f"  [Network] Fallback failed: {e}")
            return devices


def _ping(ip):
    """Return True if host responds to ping."""
    flag = "-n" if OS == "Windows" else "-c"
    timeout_flag = "-w" if OS == "Windows" else "-W"
    try:
        r = subprocess.run(
            ["ping", flag, "1", timeout_flag, "1", ip],
            capture_output=True, timeout=2
        )
        return r.returncode == 0
    except Exception:
        return False


def _resolve(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def _scan_ports(ip, ports=None, timeout=0.3):
    """Return list of open ports."""
    open_ports = []
    for port in (ports or COMMON_PORTS):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


def _read_arp_table():
    """Read the FULL ARP table and return {ip: mac} dict."""
    table = {}
    try:
        if OS == "Windows":
            out = subprocess.check_output(["arp", "-a"], timeout=4,
                                          stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip  = parts[0].strip()
                    mac = parts[1].strip()
                    if "-" in mac and len(mac) == 17:
                        table[ip] = mac.replace("-", ":").upper()
        else:
            # Linux: try /proc/net/arp first (most reliable, no subprocess)
            try:
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip  = parts[0]
                            mac = parts[3]
                            if ":" in mac and mac != "00:00:00:00:00:00":
                                table[ip] = mac.upper()
            except Exception:
                # Fallback to arp -n
                out = subprocess.check_output(["arp", "-n"], timeout=4,
                                              stderr=subprocess.DEVNULL).decode()
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        ip  = parts[0]
                        mac = parts[2]
                        if ":" in mac and len(mac) == 17:
                            table[ip] = mac.upper()
    except Exception:
        pass
    return table


def _get_mac_from_arp(ip, arp_table=None):
    """Get MAC for a single IP from ARP cache."""
    if arp_table:
        return arp_table.get(ip)
    # Single lookup fallback
    table = _read_arp_table()
    return table.get(ip)


def _vendor_from_mac(mac):
    if not mac:
        return "Unknown"
    prefix = mac[:8].upper()
    return VENDOR_MAP.get(prefix, "Unknown")


def _device_type(ip, open_ports, is_local=False, vendor="Unknown"):
    if is_local:
        return "THIS PC", "🖥️"
    # Check vendor first — phones/tablets typically have no open ports
    v = vendor.lower()
    if any(x in v for x in ["apple", "samsung", "xiaomi", "huawei", "google",
                              "realme", "oppo", "vivo", "oneplus"]):
        return "Mobile / Tablet", "📱"
    if "amazon" in v:
        return "Amazon Device (Echo/Fire)", "🔊"
    if any(x in v for x in ["tp-link", "netgear", "d-link", "asus", "linksys", "cisco"]):
        return "Router / Access Point", "📡"
    if "raspberry" in v:
        return "Raspberry Pi", "🍓"
    if any(x in v for x in ["vmware", "hyper-v"]):
        return "Virtual Machine", "💻"
    # Fall back to port-based detection
    if ip.split(".")[-1] == "1":
        return "Gateway / Router", "🌐"
    if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
        return "Web Server / Router", "🌐"
    if 22 in open_ports:
        return "Linux / SSH Device", "🐧"
    if 3389 in open_ports:
        return "Windows PC", "🪟"
    if 21 in open_ports:
        return "FTP Server", "📁"
    if open_ports:
        return "Network Device", "🖥️"
    return "Unknown Device", "📡"


def _risk_level(open_ports, is_local=False):
    if is_local:
        return "LOW"
    risky = [p for p in open_ports if p in RISKY_PORTS]
    if risky:
        return "CRITICAL"
    if 23 in open_ports:
        return "HIGH"       # Telnet
    if any(p in open_ports for p in [3306, 5432, 3389]):
        return "MEDIUM"
    if open_ports:
        return "LOW"
    return "INFO"


def _tcp_probe(ip, ports=None, timeout=0.5):
    """Quick TCP probe — returns True if any common port is open."""
    check = ports or [80, 443, 22, 445, 8080, 23, 21, 3389, 3306]
    for port in check:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def _probe_host(ip, local_ip, arp_table=None):
    """ARP-first discovery + ping + TCP fallback. Returns device dict or None."""
    is_local = (ip == local_ip)
    # Look up MAC from pre-fetched ARP table
    mac = (arp_table or {}).get(ip)
    vendor = _vendor_from_mac(mac)

    if not is_local:
        # ARP hit = device exists on network (phones block ping & TCP but ARP works)
        arp_alive = mac is not None
        if not arp_alive:
            # No ARP entry — try ping then TCP
            alive = _ping(ip)
            if not alive:
                alive = _tcp_probe(ip)
            if not alive:
                return None
    hostname   = _resolve(ip)
    # Only port-scan if we have reason to think ports are open
    # (skip for known mobile vendors — they block everything)
    v_lower = vendor.lower()
    is_mobile_vendor = any(x in v_lower for x in [
        "apple", "samsung", "xiaomi", "huawei", "google",
        "realme", "oppo", "vivo", "oneplus"
    ])
    open_ports = [] if (is_mobile_vendor and mac) else _scan_ports(ip)
    if mac is None:
        mac = _get_mac_from_arp(ip, arp_table)  # retry
        vendor = _vendor_from_mac(mac)
        v_lower = vendor.lower()
    dtype, icon = _device_type(ip, open_ports, is_local, vendor)
    risk      = _risk_level(open_ports, is_local)
    notes     = []
    if 23 in open_ports:
        notes.append("Telnet open — unencrypted!")
    if 3306 in open_ports or 5432 in open_ports:
        notes.append("Database port exposed")
    if 3389 in open_ports:
        notes.append("RDP open — restrict access")
    risky = [f"{p}({RISKY_PORTS[p]})" for p in open_ports if p in RISKY_PORTS]
    if risky:
        notes.append(f"HIGH RISK ports: {', '.join(risky)}")
    return {
        "ip":         ip,
        "hostname":   hostname if hostname != ip else "—",
        "mac":        mac or "—",
        "vendor":     vendor,
        "type":       dtype,
        "icon":       icon,
        "open_ports": open_ports,
        "risk":       risk,
        "note":       " | ".join(notes) if notes else "No issues detected",
        "is_local":   is_local,
    }


# ── Public API ─────────────────────────────────────────────────────────

def scan_network_devices():
    """Scan local subnet and return list of discovered devices."""
    devices = []
    ifaces = _get_local_interfaces()
    
    # Debug output
    print(f"  [Network] Found {len(ifaces)} interfaces: {ifaces}")

    if not ifaces:
        # Fallback - get IP using a different method
        try:
            # Create a socket to get the actual local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Determine netmask
            if local_ip.startswith('192.168.'):
                netmask = "255.255.255.0"
            elif local_ip.startswith('10.'):
                netmask = "255.0.0.0"
            elif local_ip.startswith('172.'):
                netmask = "255.255.0.0"
            else:
                netmask = "255.255.255.0"
            
            hostname = socket.gethostname()
            devices.append({
                "ip": local_ip, 
                "hostname": hostname, 
                "mac": "—",
                "vendor": "—", 
                "type": "THIS PC", 
                "icon": "🖥️",
                "open_ports": _scan_ports(local_ip),
                "risk": "LOW", 
                "note": "Your machine", 
                "is_local": True,
            })
            
            # Add router/gateway
            gateway = '.'.join(local_ip.split('.')[:-1]) + '.1'
            devices.append({
                "ip": gateway,
                "hostname": "Router/Gateway",
                "mac": "—",
                "vendor": "Unknown",
                "type": "Wi-Fi Router",
                "icon": "🌐",
                "open_ports": [80, 443],
                "risk": "INFO",
                "note": "Your Wi-Fi router - check admin panel",
                "is_local": False,
            })
            
            print(f"  [Network] Fallback: Found {len(devices)} devices")
            return devices
            
        except Exception as e:
            print(f"  [Network] Fallback failed: {e}")
            return devices

    for local_ip, netmask, iface in ifaces[:1]:   # scan first real interface
        try:
            network  = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
            # Limit to /24 or smaller to keep scan fast
            if network.num_addresses > 256:
                network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)

            hosts = list(network.hosts())
            other_ips = [str(h) for h in hosts if str(h) != local_ip]

            # ── STEP 1: UDP-seed ARP cache ─────────────────────────────
            # Send a tiny UDP packet to every IP — the kernel must ARP for each
            # one, populating /proc/net/arp even if the host never replies.
            # This is the ONLY reliable way to find phones/tablets on WiFi
            # with AP client isolation (they block ping & TCP but ARP still works).
            def _udp_seed(ip):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(0.05)
                        s.sendto(b'x', (ip, 1))
                except Exception:
                    pass

            # Fire UDP probes in parallel — very fast, just seeding ARP
            with ThreadPoolExecutor(max_workers=100) as ex:
                list(ex.map(_udp_seed, other_ips))

            # Also ping broadcast to wake up any ARP proxies
            try:
                bcast = str(network.broadcast_address)
                subprocess.run(
                    ["ping", "-n" if OS=="Windows" else "-c", "2",
                     "-w" if OS=="Windows" else "-W", "1", bcast],
                    capture_output=True, timeout=4)
            except Exception:
                pass

            # Short wait for ARP replies to arrive
            time.sleep(1.5)

            # ── STEP 2: Read the full ARP table ────────────────────────
            arp_table = _read_arp_table()

            # ── STEP 3: Probe all IPs — ARP hit = device exists ────────
            # Devices in ARP table are probed regardless of ping/TCP response
            all_probe_ips = set(other_ips)

            with ThreadPoolExecutor(max_workers=50) as ex:
                futures = {
                    ex.submit(_probe_host, ip, local_ip, arp_table): ip
                    for ip in all_probe_ips
                }
                # Add local machine immediately
                local_dev = _probe_host(local_ip, local_ip, arp_table)
                if local_dev:
                    devices.append(local_dev)
                for f in as_completed(futures, timeout=25):
                    try:
                        result = f.result()
                        if result:
                            devices.append(result)
                    except Exception:
                        pass
        except Exception:
            pass

    # Sort: local first, then by IP
    devices.sort(key=lambda d: (not d.get("is_local", False),
                                 [int(x) for x in d["ip"].split(".")
                                  if x.isdigit()]))
    return devices


def scan_usb_devices():
    """Return list of removable/USB storage devices."""
    devices = []
    if not OK:
        return devices
    try:
        for p in psutil.disk_partitions(all=False):
            opts = p.opts.lower()
            is_usb = (
                "removable" in opts
                or "usb"     in opts
                or (OS == "Windows" and p.fstype and len(p.device) == 3
                    and p.device[0].upper() not in ("C",))
            )
            if not is_usb:
                continue
            try:
                usage    = psutil.disk_usage(p.mountpoint)
                total_gb = round(usage.total / 1e9, 1)
                used_pct = round(usage.percent)
                devices.append({
                    "device":     p.device,
                    "name":       f"USB Drive ({p.device})",
                    "device_type":"USB Storage",
                    "mountpoint": p.mountpoint,
                    "fstype":     p.fstype,
                    "size_gb":    total_gb,
                    "used_pct":   used_pct,
                    "detail":     f"{total_gb} GB · {used_pct}% used · {p.fstype}",
                    "icon":       "💾",
                    "risk":       "MEDIUM",
                    "note":       "Scan for malware before opening files",
                })
            except Exception:
                devices.append({
                    "device":     p.device,
                    "name":       f"USB Drive ({p.device})",
                    "device_type":"USB Storage",
                    "detail":     "Could not read usage",
                    "icon":       "💾",
                    "risk":       "MEDIUM",
                    "note":       "Scan for malware before opening files",
                })
    except Exception:
        pass
    return devices


def run_scan():
    return {
        "network": scan_network_devices(),
        "usb":     scan_usb_devices(),
        "scanned_at": time.strftime("%H:%M:%S"),
    }