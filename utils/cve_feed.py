# utils/cve_feed.py - CVE Vulnerability Feed
import requests
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict

CVE_CACHE_FILE = "cve_cache.json"
CVE_CACHE_TTL = 86400  # 24 hours

class CVEFeed:
    """NVD CVE Feed Integration"""
    
    def __init__(self):
        self.cache = self._load_cache()
        self.port_cve_map = {
            22: ["ssh", "openssh"],
            23: ["telnet"],
            80: ["http", "apache", "nginx", "iis"],
            443: ["https", "apache", "nginx", "iis", "openssl"],
            3306: ["mysql", "mariadb"],
            5432: ["postgresql"],
            6379: ["redis"],
            3389: ["rdp", "remote desktop"],
            8080: ["tomcat", "jetty", "spring"],
            21: ["ftp", "proftpd", "vsftpd"],
            25: ["smtp", "postfix", "sendmail"],
            110: ["pop3"],
            143: ["imap"],
            445: ["smb", "samba"],
            139: ["netbios"],
            135: ["rpc"],
        }
    
    def _load_cache(self):
        """Load cached CVE data"""
        try:
            with open(CVE_CACHE_FILE, 'r') as f:
                cache = json.load(f)
                # Check expiry
                if time.time() - cache.get("timestamp", 0) < CVE_CACHE_TTL:
                    return cache.get("data", {})
        except:
            pass
        return {}
    
    def _save_cache(self, data):
        """Save CVE data to cache"""
        try:
            with open(CVE_CACHE_FILE, 'w') as f:
                json.dump({
                    "timestamp": time.time(),
                    "data": data
                }, f)
        except:
            pass
    
    def get_cves_for_keyword(self, keyword, limit=10):
        """Get CVEs for a specific keyword from NVD API"""
        cache_key = f"keyword_{keyword}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": limit
            }
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    metrics = cve.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
                    
                    cves.append({
                        "id": cve.get("id", ""),
                        "description": cve.get("descriptions", [{}])[0].get("value", ""),
                        "published": cve.get("published", ""),
                        "last_modified": cve.get("lastModified", ""),
                        "cvss_v3_score": cvss_v3.get("baseScore", 0),
                        "cvss_v3_severity": cvss_v3.get("baseSeverity", "UNKNOWN"),
                        "cvss_v2_score": cvss_v2.get("baseScore", 0),
                        "cvss_v2_severity": cvss_v2.get("severity", "UNKNOWN"),
                        "exploitability_score": metrics.get("cvssMetricV31", [{}])[0].get("exploitabilityScore", 0),
                        "impact_score": metrics.get("cvssMetricV31", [{}])[0].get("impactScore", 0),
                        "cwe": cve.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", ""),
                        "references": [ref.get("url", "") for ref in cve.get("references", [])[:5]],
                    })
                
                self.cache[cache_key] = cves
                self._save_cache(self.cache)
                return cves
            else:
                return []
        except Exception as e:
            print(f"  [CVE] Error fetching CVEs: {e}")
            return []
    
    def get_cves_for_port(self, port):
        """Get CVEs relevant to a specific port"""
        if port not in self.port_cve_map:
            return []
        
        keywords = self.port_cve_map[port]
        all_cves = []
        for kw in keywords:
            cves = self.get_cves_for_keyword(kw, limit=5)
            all_cves.extend(cves)
        
        # Deduplicate by ID
        seen = set()
        unique_cves = []
        for cve in all_cves:
            if cve["id"] not in seen:
                seen.add(cve["id"])
                unique_cves.append(cve)
        
        # Sort by CVSS score
        unique_cves.sort(key=lambda x: x.get("cvss_v3_score", 0), reverse=True)
        return unique_cves[:10]
    
    def get_recent_cves(self, days=7, limit=20):
        """Get recent CVEs from the last N days"""
        try:
            start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "pubStartDate": start_date,
                "resultsPerPage": limit
            }
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    metrics = cve.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    
                    cves.append({
                        "id": cve.get("id", ""),
                        "description": cve.get("descriptions", [{}])[0].get("value", "")[:200],
                        "published": cve.get("published", ""),
                        "cvss_v3_score": cvss_v3.get("baseScore", 0),
                        "cvss_v3_severity": cvss_v3.get("baseSeverity", "UNKNOWN"),
                    })
                return cves
            return []
        except Exception as e:
            return []
    
    def check_affected_services(self, open_ports):
        """Check which open ports have known vulnerabilities"""
        results = {}
        for port in open_ports:
            cves = self.get_cves_for_port(port)
            if cves:
                results[port] = {
                    "cve_count": len(cves),
                    "highest_severity": max([c.get("cvss_v3_severity", "LOW") for c in cves]) if cves else "NONE",
                    "highest_score": max([c.get("cvss_v3_score", 0) for c in cves]) if cves else 0,
                    "cves": cves[:3]
                }
        return results

# Global instance
cve_feed = CVEFeed()
