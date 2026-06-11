# utils/threat_intel.py - Threat Intelligence Integration
import requests
import json
import time
import hashlib
import os
from datetime import datetime, timedelta
from collections import defaultdict

# API Keys - Store these in environment variables or config file
CONFIG = {
    "virustotal_api_key": os.environ.get("VT_API_KEY", ""),
    "abuseipdb_api_key": os.environ.get("ABUSEIPDB_API_KEY", ""),
    "shodan_api_key": os.environ.get("SHODAN_API_KEY", ""),
    "alienvault_api_key": os.environ.get("OTX_API_KEY", ""),
}

# Cache to avoid rate limiting
_cache = {}
_cache_expiry = {}

def _get_cache(key, ttl=300):
    """Get cached value if not expired"""
    if key in _cache and _cache_expiry.get(key, 0) > time.time():
        return _cache[key]
    return None

def _set_cache(key, value, ttl=300):
    """Set cache with expiry"""
    _cache[key] = value
    _cache_expiry[key] = time.time() + ttl

# ==================== VirusTotal Integration ====================

def virustotal_lookup_ip(ip):
    """Look up IP in VirusTotal"""
    if not CONFIG["virustotal_api_key"]:
        return {"error": "VirusTotal API key not configured"}
    
    cache_key = f"vt_ip_{ip}"
    cached = _get_cache(cache_key, ttl=3600)  # Cache for 1 hour
    if cached:
        return cached
    
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": CONFIG["virustotal_api_key"]}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            result = {
                "ip": ip,
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "country": attributes.get("country", "Unknown"),
                "asn": attributes.get("asn", "Unknown"),
                "as_owner": attributes.get("as_owner", "Unknown"),
                "reputation": attributes.get("reputation", 0),
                "total_votes": attributes.get("total_votes", {}),
                "last_analysis_date": attributes.get("last_analysis_date", 0),
                "analysis_results": attributes.get("last_analysis_results", {})[:10],
            }
            _set_cache(cache_key, result, 3600)
            return result
        else:
            return {"error": f"VirusTotal API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def virustotal_lookup_hash(file_hash):
    """Look up file hash in VirusTotal"""
    if not CONFIG["virustotal_api_key"]:
        return {"error": "VirusTotal API key not configured"}
    
    cache_key = f"vt_hash_{file_hash}"
    cached = _get_cache(cache_key, ttl=86400)  # Cache for 24 hours
    if cached:
        return cached
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": CONFIG["virustotal_api_key"]}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            result = {
                "hash": file_hash,
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "type": attributes.get("type_tag", "Unknown"),
                "size": attributes.get("size", 0),
                "names": attributes.get("names", [])[:5],
                "signature_info": attributes.get("signature_info", {}),
                "first_submission_date": attributes.get("first_submission_date", 0),
                "last_submission_date": attributes.get("last_submission_date", 0),
                "tags": attributes.get("tags", [])[:10],
                "crowdsourced_ids_stats": attributes.get("crowdsourced_ids_stats", {}),
            }
            _set_cache(cache_key, result, 86400)
            return result
        else:
            return {"error": f"VirusTotal API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ==================== AbuseIPDB Integration ====================

def abuseipdb_lookup(ip):
    """Look up IP in AbuseIPDB"""
    if not CONFIG["abuseipdb_api_key"]:
        return {"error": "AbuseIPDB API key not configured"}
    
    cache_key = f"abuse_{ip}"
    cached = _get_cache(cache_key, ttl=3600)
    if cached:
        return cached
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
        headers = {"Key": CONFIG["abuseipdb_api_key"], "Accept": "application/json"}
        response = requests.get(url, headers=headers, params=querystring, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            result = {
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode", "Unknown"),
                "country_name": data.get("countryName", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "last_reported_at": data.get("lastReportedAt", ""),
                "usage_type": data.get("usageType", "Unknown"),
                "reports": data.get("reports", [])[:5],
                "is_whitelisted": data.get("isWhitelisted", False),
            }
            _set_cache(cache_key, result, 3600)
            return result
        else:
            return {"error": f"AbuseIPDB API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ==================== Shodan Integration ====================

def shodan_lookup(ip):
    """Look up IP in Shodan"""
    if not CONFIG["shodan_api_key"]:
        return {"error": "Shodan API key not configured"}
    
    cache_key = f"shodan_{ip}"
    cached = _get_cache(cache_key, ttl=7200)
    if cached:
        return cached
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={CONFIG['shodan_api_key']}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            result = {
                "ip": ip,
                "country": data.get("country_name", "Unknown"),
                "city": data.get("city", "Unknown"),
                "org": data.get("org", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "asn": data.get("asn", "Unknown"),
                "hostnames": data.get("hostnames", [])[:5],
                "domains": data.get("domains", [])[:5],
                "ports": data.get("ports", [])[:20],
                "vulns": list(data.get("vulns", {}).keys())[:10],
                "tags": data.get("tags", []),
                "os": data.get("os", "Unknown"),
                "last_update": data.get("last_update", ""),
                "data": data.get("data", [])[:5],
            }
            _set_cache(cache_key, result, 7200)
            return result
        elif response.status_code == 404:
            return {"error": "IP not found in Shodan"}
        else:
            return {"error": f"Shodan API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ==================== AlienVault OTX Integration ====================

def alienvault_lookup(ip):
    """Look up IP in AlienVault OTX"""
    if not CONFIG["alienvault_api_key"]:
        return {"error": "AlienVault OTX API key not configured"}
    
    cache_key = f"otx_{ip}"
    cached = _get_cache(cache_key, ttl=7200)
    if cached:
        return cached
    
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": CONFIG["alienvault_api_key"]}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            result = {
                "ip": ip,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "pulses": data.get("pulse_info", {}).get("pulses", [])[:10],
                "reputation": data.get("reputation", {}),
                "validation": data.get("validation", {}),
                "geo": data.get("geo", {}),
                "asn": data.get("asn", ""),
                "country_code": data.get("country_code", ""),
                "country_name": data.get("country_name", ""),
            }
            _set_cache(cache_key, result, 7200)
            return result
        else:
            return {"error": f"AlienVault API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ==================== GeoIP Integration ====================

def geoip_lookup(ip):
    """Get GeoIP information (free, no API key required)"""
    cache_key = f"geo_{ip}"
    cached = _get_cache(cache_key, ttl=86400)
    if cached:
        return cached
    
    try:
        # Using free ip-api.com (45 requests per minute limit)
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                result = {
                    "ip": ip,
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "latitude": data.get("lat", 0),
                    "longitude": data.get("lon", 0),
                    "timezone": data.get("timezone", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                }
                _set_cache(cache_key, result, 86400)
                return result
            else:
                return {"error": "GeoIP lookup failed"}
        else:
            return {"error": f"GeoIP API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ==================== Threat Intelligence Aggregator ====================

def get_comprehensive_threat_intel(ip):
    """Get threat intelligence from all sources"""
    results = {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "geoip": {},
        "abuseipdb": {},
        "virustotal": {},
        "shodan": {},
        "alienvault": {},
    }
    
    # GeoIP (always try, free)
    results["geoip"] = geoip_lookup(ip)
    
    # AbuseIPDB
    abuse = abuseipdb_lookup(ip)
    if not abuse.get("error"):
        results["abuseipdb"] = abuse
        results["abuse_confidence"] = abuse.get("abuse_confidence_score", 0)
    
    # VirusTotal
    vt = virustotal_lookup_ip(ip)
    if not vt.get("error"):
        results["virustotal"] = vt
        results["vt_malicious"] = vt.get("malicious", 0)
    
    # Shodan (if API key configured)
    if CONFIG["shodan_api_key"]:
        shodan = shodan_lookup(ip)
        if not shodan.get("error"):
            results["shodan"] = shodan
    
    # AlienVault (if API key configured)
    if CONFIG["alienvault_api_key"]:
        otx = alienvault_lookup(ip)
        if not otx.get("error"):
            results["alienvault"] = otx
    
    # Calculate overall risk score
    risk_score = 0
    if results.get("abuse_confidence", 0) > 50:
        risk_score += 30
    if results.get("vt_malicious", 0) > 0:
        risk_score += min(40, results["vt_malicious"] * 10)
    if results.get("abuse_confidence", 0) > 80:
        risk_score += 30
    
    results["overall_risk_score"] = min(100, risk_score)
    results["risk_level"] = "CRITICAL" if risk_score > 70 else "HIGH" if risk_score > 40 else "MEDIUM" if risk_score > 20 else "LOW"
    
    return results