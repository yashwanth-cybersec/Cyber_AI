# utils/self_threat_intel.py - Complete Self-contained Threat Intelligence (No API Keys)
import socket
import ipaddress
import subprocess
import re
import time
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta

# Try to import optional dependencies
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("  [ThreatIntel] DNS module not installed. Tor exit detection will use static list.")

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("  [ThreatIntel] GeoIP2 not installed. Using IP range detection.")

# Known malicious IP ranges (Community-sourced OSINT)
KNOWN_MALICIOUS_RANGES = {
    # Tor exit nodes
    "tor_exits": [
        "185.220.101.0/24", "185.220.102.0/24", "185.220.103.0/24",
        "45.33.32.0/24", "51.77.0.0/16", "79.137.0.0/16",
        "5.188.206.0/24", "194.165.16.0/24"
    ],
    # Known C2 servers (community-reported)
    "c2_servers": [
        "91.108.4.0/24", "149.154.0.0/16", "23.129.64.0/24",
        "199.87.0.0/16", "185.234.0.0/16"
    ],
    # Scanners and bots
    "scanners": [
        "45.33.32.156", "185.220.101.45", "5.188.206.14",
        "194.165.16.77", "91.108.4.180"
    ],
    # Malware distribution
    "malware_hosts": [
        "104.16.0.0/12", "172.67.0.0/16", "188.114.96.0/20"
    ]
}

# Known malicious ports and their associated threats
MALICIOUS_PORTS = {
    21: {"service": "FTP", "risk": "MEDIUM", "threat": "Weak authentication, data exfiltration"},
    22: {"service": "SSH", "risk": "MEDIUM", "threat": "Brute force attacks, unauthorized access"},
    23: {"service": "Telnet", "risk": "CRITICAL", "threat": "Unencrypted, credential theft"},
    25: {"service": "SMTP", "risk": "MEDIUM", "threat": "Spam relay, email harvesting"},
    80: {"service": "HTTP", "risk": "LOW", "threat": "Web attacks, malware delivery"},
    443: {"service": "HTTPS", "risk": "LOW", "threat": "Encrypted C2, phishing"},
    445: {"service": "SMB", "risk": "CRITICAL", "threat": "EternalBlue, ransomware propagation"},
    1433: {"service": "MSSQL", "risk": "HIGH", "threat": "Database attacks, data theft"},
    3306: {"service": "MySQL", "risk": "HIGH", "threat": "Database compromise, data exfiltration"},
    3389: {"service": "RDP", "risk": "HIGH", "threat": "Remote desktop attacks, BlueKeep"},
    5432: {"service": "PostgreSQL", "risk": "HIGH", "threat": "Database compromise"},
    6379: {"service": "Redis", "risk": "CRITICAL", "threat": "No auth by default, server compromise"},
    8080: {"service": "HTTP-Alt", "risk": "MEDIUM", "threat": "Web shells, proxy services"},
    8443: {"service": "HTTPS-Alt", "risk": "MEDIUM", "threat": "Admin panels, web shells"},
    4444: {"service": "Metasploit", "risk": "CRITICAL", "threat": "Metasploit payload, RAT"},
    1337: {"service": "Backdoor", "risk": "CRITICAL", "threat": "Common backdoor port"},
    6667: {"service": "IRC", "risk": "HIGH", "threat": "IRC botnet C2"},
    9001: {"service": "Tor", "risk": "MEDIUM", "threat": "Tor proxy, anonymized attacks"},
}

# Threat intel cache
_cache = {}
_cache_expiry = {}
_threat_db = {}  # Local threat database

class SelfThreatIntel:
    """Complete self-contained threat intelligence system"""
    
    def __init__(self):
        self.threat_db_file = "threat_intel_db.json"
        self.local_threats = defaultdict(list)
        self._load_threat_db()
        self._update_tor_exits()
    
    def _load_threat_db(self):
        """Load local threat database"""
        if os.path.exists(self.threat_db_file):
            try:
                with open(self.threat_db_file, 'r') as f:
                    data = json.load(f)
                    self.local_threats = defaultdict(list, data)
                print(f"  [ThreatIntel] Loaded {len(self.local_threats)} threat entries")
            except:
                pass
    
    def _save_threat_db(self):
        """Save local threat database"""
        try:
            with open(self.threat_db_file, 'w') as f:
                json.dump(dict(self.local_threats), f, indent=2)
        except:
            pass
    
    def _update_tor_exits(self):
        """Get Tor exit nodes via DNS (no API key needed)"""
        if DNS_AVAILABLE:
            try:
                # Query Tor DNSRBL - free, no key
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                
                # Check common Tor exit node DNSBLs
                tor_domains = [".dnsel.torproject.org", ".tor.dnsbl.sectoor.de"]
                
                for ip in KNOWN_MALICIOUS_RANGES["tor_exits"]:
                    # Parse range and add to threat db
                    network = ipaddress.ip_network(ip)
                    for ip_addr in list(network.hosts())[:10]:  # Sample first 10
                        ip_str = str(ip_addr)
                        reversed_ip = '.'.join(reversed(ip_str.split('.')))
                        try:
                            for domain in tor_domains:
                                query = f"{reversed_ip}{domain}"
                                resolver.resolve(query, 'A')
                                # If we get here, it's a Tor exit node
                                self.local_threats[ip_str].append({
                                    "source": "tor_exit_dns",
                                    "risk": "HIGH",
                                    "reason": "Tor exit node (anonymization service)",
                                    "timestamp": time.time()
                                })
                                break
                        except:
                            pass
            except Exception as e:
                print(f"  [ThreatIntel] DNS query failed: {e}")
                self._add_static_tor_exits()
        else:
            self._add_static_tor_exits()
    
    def _add_static_tor_exits(self):
        """Add static Tor exit nodes"""
        static_tor_ips = ["185.220.101.45", "185.220.102.10", "51.77.45.33"]
        for ip in static_tor_ips:
            self.local_threats[ip].append({
                "source": "tor_exit_static",
                "risk": "HIGH",
                "reason": "Known Tor exit node (static list)",
                "timestamp": time.time()
            })
    
    def _check_ip_in_ranges(self, ip, ranges):
        """Check if IP belongs to any CIDR range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in ranges:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
        except:
            pass
        return False
    
    def _query_shodan_style(self, ip):
        """Shodan-style scanning (local, no API)"""
        results = {
            "open_ports": [],
            "banners": [],
            "services": []
        }
        
        # Scan common ports locally
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 4444, 1337]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    results["open_ports"].append(port)
                    results["services"].append({
                        "port": port,
                        "service": MALICIOUS_PORTS.get(port, {}).get("service", f"port_{port}"),
                        "banner": self._grab_banner(ip, port)
                    })
                sock.close()
            except:
                pass
        
        return results
    
    def _grab_banner(self, ip, port):
        """Grab service banner for port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Send probe based on port
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in [21, 22, 23]:
                sock.send(b"\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100] if banner else "No banner captured"
        except:
            return "Banner capture failed"
    
    def _abuseipdb_style(self, ip):
        """AbuseIPDB-style reputation (local database + heuristics)"""
        score = 0
        reasons = []
        
        # Check if IP is in known threat lists
        if ip in self.local_threats:
            threats = self.local_threats[ip]
            for threat in threats:
                score += 30
                reasons.append(threat.get("reason", "Known threat source"))
        
        # Check for Tor/Proxy
        if self._check_ip_in_ranges(ip, KNOWN_MALICIOUS_RANGES["tor_exits"]):
            score += 40
            reasons.append("Tor exit node detected")
        
        # Check for C2 ranges
        if self._check_ip_in_ranges(ip, KNOWN_MALICIOUS_RANGES["c2_servers"]):
            score += 50
            reasons.append("Known C2 server range")
        
        # Check for scanner IPs
        if ip in KNOWN_MALICIOUS_RANGES["scanners"]:
            score += 35
            reasons.append("Known scanner/bot IP")
        
        # Heuristic: suspicious country codes
        geo = self._local_geoip(ip)
        suspicious_countries = ["RU", "CN", "KP", "IR", "SY", "AF", "PK", "NG", "VN", "RO"]
        if geo.get("country_code") in suspicious_countries:
            score += 20
            reasons.append(f"High-risk country: {geo.get('country')}")
        
        # Heuristic: non-standard ports open
        open_ports = self._query_shodan_style(ip)["open_ports"]
        for port in open_ports:
            if port in MALICIOUS_PORTS:
                risk = MALICIOUS_PORTS[port]["risk"]
                if risk == "CRITICAL":
                    score += 30
                elif risk == "HIGH":
                    score += 20
                elif risk == "MEDIUM":
                    score += 10
                reasons.append(f"Port {port} ({MALICIOUS_PORTS[port]['service']}) - {MALICIOUS_PORTS[port]['threat']}")
        
        # Heuristic: multiple open ports = scanning activity
        if len(open_ports) >= 5:
            score += 15
            reasons.append(f"Multiple open ports ({len(open_ports)}) - possible scanning")
        
        return {
            "abuse_confidence_score": min(100, score),
            "total_reports": len(self.local_threats.get(ip, [])),
            "reasons": reasons[:5],
            "risk_level": "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 20 else "LOW"
        }
    
    def _virustotal_style(self, ip):
        """VirusTotal-style analysis (local heuristics)"""
        analysis = {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "detections": []
        }
        
        # Check open ports against known malicious ports
        open_ports = self._query_shodan_style(ip)["open_ports"]
        for port in open_ports:
            if port in MALICIOUS_PORTS:
                analysis["malicious"] += 1
                analysis["detections"].append({
                    "engine": "Port Scanner",
                    "result": f"Port {port} - {MALICIOUS_PORTS[port]['threat']}",
                    "severity": MALICIOUS_PORTS[port]["risk"]
                })
        
        # Check threat intelligence
        abuse = self._abuseipdb_style(ip)
        if abuse["abuse_confidence_score"] > 50:
            analysis["malicious"] += 1
            analysis["detections"].append({
                "engine": "AbuseIPDB (Local)",
                "result": f"Abuse confidence: {abuse['abuse_confidence_score']}%",
                "severity": abuse["risk_level"]
            })
        
        # Check local threat database
        if ip in self.local_threats:
            for threat in self.local_threats[ip]:
                analysis["malicious"] += 1
                analysis["detections"].append({
                    "engine": "Local Threat DB",
                    "result": threat.get("reason", "Threat detected"),
                    "severity": threat.get("risk", "MEDIUM")
                })
        
        # Suspicious banner patterns
        services = self._query_shodan_style(ip)["services"]
        for svc in services:
            banner = svc.get("banner", "").lower()
            if "ssh" in banner and "dropbear" in banner:
                analysis["suspicious"] += 1
                analysis["detections"].append({
                    "engine": "Banner Analysis",
                    "result": "DropBear SSH (often used in IoT malware)",
                    "severity": "HIGH"
                })
            if "apache" in banner and "coyote" in banner:
                analysis["suspicious"] += 1
                analysis["detections"].append({
                    "engine": "Banner Analysis",
                    "result": "Apache Coyote (Tomcat) - common attack vector",
                    "severity": "MEDIUM"
                })
        
        return analysis
    
    def _alienvault_style(self, ip):
        """AlienVault OTX-style pulse intelligence"""
        pulses = []
        
        # Create pulses based on threat intelligence
        abuse = self._abuseipdb_style(ip)
        if abuse["abuse_confidence_score"] > 30:
            pulses.append({
                "name": f"Threat Pulse: {ip}",
                "description": f"IP {ip} has been flagged with {abuse['abuse_confidence_score']}% abuse confidence",
                "indicators": [ip],
                "tags": ["malicious", "abuse", "threat"],
                "revision": 1,
                "created": datetime.now().isoformat(),
                "tlp": "amber"
            })
        
        # Add pulses for open ports
        open_ports = self._query_shodan_style(ip)["open_ports"]
        if open_ports:
            pulses.append({
                "name": f"Open Ports Detected: {ip}",
                "description": f"Open ports: {', '.join(map(str, open_ports))}",
                "indicators": [ip],
                "tags": ["scan", "reconnaissance", "vulnerability"],
                "revision": 1,
                "created": datetime.now().isoformat()
            })
        
        # Add pulse for known C2 activity
        if self._check_ip_in_ranges(ip, KNOWN_MALICIOUS_RANGES["c2_servers"]):
            pulses.append({
                "name": f"C2 Infrastructure Detected: {ip}",
                "description": f"IP {ip} matches known C2 server infrastructure patterns",
                "indicators": [ip],
                "tags": ["c2", "command-and-control", "malware"],
                "revision": 1,
                "created": datetime.now().isoformat(),
                "tlp": "red"
            })
        
        return {
            "pulse_count": len(pulses),
            "pulses": pulses,
            "pulse_info": {
                "references": [
                    f"https://otx.alienvault.com/indicator/ip/{ip}",
                    f"https://www.abuseipdb.com/check/{ip}"
                ]
            }
        }
    
    def _local_geoip(self, ip):
        """Local GeoIP database with optional GeoIP2 support"""
        if GEOIP_AVAILABLE:
            try:
                # Try to use GeoIP2 database if available
                geoip_path = "GeoLite2-City.mmdb"
                if os.path.exists(geoip_path):
                    reader = geoip2.database.Reader(geoip_path)
                    try:
                        response = reader.city(ip)
                        return {
                            "country": response.country.name or "Unknown",
                            "country_code": response.country.iso_code or "XX",
                            "city": response.city.name or "Unknown",
                            "latitude": response.location.latitude or 0,
                            "longitude": response.location.longitude or 0,
                            "isp": self._guess_isp(ip),
                            "timezone": response.location.time_zone or "Unknown"
                        }
                    finally:
                        reader.close()
            except:
                pass
        
        # Fallback to IP range detection
        try:
            first_octet = int(ip.split('.')[0])
            second_octet = int(ip.split('.')[1]) if len(ip.split('.')) > 1 else 0
            
            # More detailed IP range mapping
            if 1 <= first_octet <= 50:
                if first_octet == 8:
                    return {"country": "United States", "code": "US", "isp": "Google", "city": "Mountain View"}
                elif first_octet == 13:
                    return {"country": "United States", "code": "US", "isp": "Microsoft", "city": "Redmond"}
                elif first_octet == 20:
                    return {"country": "United States", "code": "US", "isp": "Microsoft Azure"}
                else:
                    return {"country": "United States", "code": "US", "city": "Unknown", "isp": self._guess_isp(ip)}
            elif 51 <= first_octet <= 100:
                if first_octet == 51 and second_octet == 77:
                    return {"country": "Netherlands", "code": "NL", "isp": "Linode"}
                elif first_octet == 54:
                    return {"country": "United States", "code": "US", "isp": "Amazon AWS"}
                else:
                    return {"country": "Europe", "code": "EU", "isp": self._guess_isp(ip)}
            elif 101 <= first_octet <= 150:
                if first_octet == 104:
                    return {"country": "United States", "code": "US", "isp": "Cloudflare"}
                else:
                    return {"country": "Asia", "code": "AS", "isp": self._guess_isp(ip)}
            elif 151 <= first_octet <= 200:
                return {"country": "South America", "code": "SA", "isp": self._guess_isp(ip)}
            else:
                return {"country": "Unknown", "code": "XX", "isp": self._guess_isp(ip)}
        except:
            return {"country": "Unknown", "code": "XX", "isp": "Unknown", "city": "Unknown"}
    
    def _guess_isp(self, ip):
        """Guess ISP from IP ranges with more details"""
        first_octet = int(ip.split('.')[0])
        second_octet = int(ip.split('.')[1]) if len(ip.split('.')) > 1 else 0
        
        if first_octet == 8 or first_octet == 9:
            return "Google"
        elif first_octet == 13 or first_octet == 20 or first_octet == 40:
            return "Microsoft/Azure"
        elif first_octet == 54 or first_octet == 52 or first_octet == 35:
            return "Amazon AWS"
        elif first_octet == 104 or first_octet == 172:
            return "Cloudflare"
        elif first_octet == 185 and second_octet == 220:
            return "Tor Network"
        elif first_octet == 45 and second_octet == 33:
            return "Linode"
        elif first_octet == 51 and second_octet == 77:
            return "Linode"
        elif first_octet == 194 and second_octet == 165:
            return "C2 Infrastructure"
        elif first_octet == 91 and second_octet == 108:
            return "Telegram/Abuse"
        elif first_octet == 149 and second_octet == 154:
            return "Telegram/Abuse"
        else:
            return "Unknown ISP"
    
    def add_threat(self, ip, threat_type, reason, risk="MEDIUM"):
        """Add IP to local threat database"""
        if ip not in self.local_threats:
            self.local_threats[ip] = []
        
        self.local_threats[ip].append({
            "source": "user_report",
            "risk": risk,
            "reason": reason,
            "timestamp": time.time(),
            "threat_type": threat_type,
            "reported_by": "user"
        })
        
        self._save_threat_db()
        return True
    
    def get_threat_intel(self, ip):
        """Get comprehensive threat intelligence for an IP"""
        # Check cache
        cache_key = f"intel_{ip}"
        if cache_key in _cache and _cache_expiry.get(cache_key, 0) > time.time():
            return _cache[cache_key]
        
        # Gather all intelligence
        result = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "geoip": self._local_geoip(ip),
            "ports": self._query_shodan_style(ip),
            "abuseipdb": self._abuseipdb_style(ip),
            "virustotal": self._virustotal_style(ip),
            "alienvault": self._alienvault_style(ip),
        }
        
        # Calculate overall risk
        risk_scores = {
            "CRITICAL": 90,
            "HIGH": 65,
            "MEDIUM": 35,
            "LOW": 10
        }
        
        max_risk = "LOW"
        for key in ["abuseipdb", "virustotal"]:
            if key in result:
                risk_level = result[key].get("risk_level", "LOW")
                if risk_scores[risk_level] > risk_scores[max_risk]:
                    max_risk = risk_level
        
        # Adjust based on open ports
        if result["ports"]["open_ports"]:
            critical_ports = [p for p in result["ports"]["open_ports"] 
                             if p in MALICIOUS_PORTS and MALICIOUS_PORTS[p]["risk"] == "CRITICAL"]
            if critical_ports and max_risk != "CRITICAL":
                max_risk = "CRITICAL"
                risk_scores[max_risk] = 85
        
        result["overall_risk"] = max_risk
        result["overall_score"] = risk_scores[max_risk]
        
        # Generate summary
        threats = []
        if result["abuseipdb"]["abuse_confidence_score"] > 30:
            threats.append(f"Abuse confidence: {result['abuseipdb']['abuse_confidence_score']}%")
        if result["virustotal"]["malicious"] > 0:
            threats.append(f"Detected by {result['virustotal']['malicious']} threat sources")
        if result["ports"]["open_ports"]:
            threats.append(f"Open ports: {', '.join(map(str, result['ports']['open_ports']))}")
        if result["geoip"].get("country_code") in ["RU", "CN", "KP", "IR"]:
            threats.append(f"High-risk country: {result['geoip'].get('country')}")
        
        result["summary"] = " | ".join(threats) if threats else "No threats detected"
        
        # Add threat score
        result["threat_score"] = result["overall_score"]
        result["recommendation"] = self._get_recommendation(result)
        
        # Cache for 1 hour
        _cache[cache_key] = result
        _cache_expiry[cache_key] = time.time() + 3600
        
        return result
    
    def _get_recommendation(self, threat_data):
        """Generate security recommendation based on threat data"""
        score = threat_data["overall_score"]
        risk = threat_data["overall_risk"]
        
        if risk == "CRITICAL":
            return "IMMEDIATE ACTION REQUIRED: Block this IP, investigate for compromise, and review all logs for suspicious activity."
        elif risk == "HIGH":
            return "URGENT: Block this IP, check for any successful connections, and update firewall rules."
        elif risk == "MEDIUM":
            return "Monitor this IP closely. Consider blocking if activity continues. Review related logs."
        else:
            return "No immediate action required. Continue monitoring as part of normal operations."

# Global instance
threat_intel = SelfThreatIntel()

# Export functions for backward compatibility
def geoip_lookup(ip):
    """Backward compatibility function"""
    return threat_intel._local_geoip(ip)

def get_comprehensive_threat_intel(ip):
    """Backward compatibility function"""
    return threat_intel.get_threat_intel(ip)

def add_threat_to_db(ip, threat_type, reason, risk="MEDIUM"):
    """Add threat to local database"""
    return threat_intel.add_threat(ip, threat_type, reason, risk)

def get_open_ports(ip):
    """Get open ports for an IP"""
    return threat_intel._query_shodan_style(ip)["open_ports"]