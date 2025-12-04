"""
External API integrations for enhanced malware analysis
Free tier APIs:
- VirusTotal: Hash-based lookups (4 req/min, 500/day)
- Abuse.ch MalwareBazaar: Sample information (unlimited)
- URLScan.io: URL scanning (100/day)
- IP-API: IP geolocation and threat intel (45 req/min)
"""

import os
import hashlib
import requests
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import re
import socket

# API Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
MALWARBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1"
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
IP_API_URL = "http://ip-api.com/json"

# Rate limiting
_last_vt_request = 0
_vt_request_interval = 15  # 4 requests per minute = 15 seconds between requests


def calculate_file_hashes(file_path: str) -> Dict[str, str]:
    """Calculate MD5, SHA1, and SHA256 hashes of a file"""
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)
        
        return {
            "md5": hash_md5.hexdigest(),
            "sha1": hash_sha1.hexdigest(),
            "sha256": hash_sha256.hexdigest()
        }
    except Exception as e:
        print(f"Error calculating hashes: {e}")
        return {}


def check_virustotal(file_hash: str) -> Optional[Dict]:
    """Check file hash against VirusTotal (free tier: 4 req/min)"""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    global _last_vt_request
    current_time = time.time()
    
    # Rate limiting
    if current_time - _last_vt_request < _vt_request_interval:
        return None
    
    try:
        url = f"https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            "apikey": VIRUSTOTAL_API_KEY,
            "resource": file_hash
        }
        
        response = requests.get(url, params=params, timeout=10)
        _last_vt_request = time.time()
        
        if response.status_code == 200:
            data = response.json()
            if data.get("response_code") == 1:  # File found
                return {
                    "detected": data.get("positives", 0),
                    "total": data.get("total", 0),
                    "scan_date": data.get("scan_date"),
                    "permalink": data.get("permalink"),
                    "scans": data.get("scans", {})
                }
        elif response.status_code == 204:
            # Rate limit exceeded
            return None
        
    except Exception as e:
        print(f"VirusTotal API error: {e}")
    
    return None


def check_malwarebazaar(file_hash: str) -> Optional[Dict]:
    """Check file hash against Abuse.ch MalwareBazaar (free, unlimited)"""
    try:
        url = f"{MALWARBAZAAR_API_URL}/"
        data = {
            "query": "get_info",
            "hash": file_hash
        }
        
        response = requests.post(url, data=data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("query_status") == "ok" and result.get("data"):
                sample = result["data"][0]
                return {
                    "sha256_hash": sample.get("sha256_hash"),
                    "md5_hash": sample.get("md5_hash"),
                    "first_seen": sample.get("first_seen"),
                    "last_seen": sample.get("last_seen"),
                    "file_name": sample.get("file_name"),
                    "file_type": sample.get("file_type"),
                    "signature": sample.get("signature"),
                    "tags": sample.get("tags", []),
                    "intelligence": {
                        "clamav": sample.get("clamav"),
                        "yara": sample.get("yara_rules", []),
                        "vendor_intel": sample.get("vendor_intel", {})
                    }
                }
    
    except Exception as e:
        print(f"MalwareBazaar API error: {e}")
    
    return None


def scan_url_with_urlscan(url: str) -> Optional[Dict]:
    """Scan URL with URLScan.io (free tier: 100/day)"""
    if not URLSCAN_API_KEY:
        return None
    
    try:
        # Submit URL for scanning
        submit_url = "https://urlscan.io/api/v1/scan/"
        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }
        data = {
            "url": url,
            "visibility": "public"
        }
        
        response = requests.post(submit_url, headers=headers, json=data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            scan_uuid = result.get("uuid")
            
            if scan_uuid:
                # Wait a bit and get results (URLScan needs time to process)
                time.sleep(5)
                result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
                
                # Try up to 3 times with increasing delays
                for attempt in range(3):
                    result_response = requests.get(result_url, timeout=10)
                    
                    if result_response.status_code == 200:
                        scan_result = result_response.json()
                        page_data = scan_result.get("page", {})
                        verdicts = scan_result.get("verdicts", {})
                        overall = verdicts.get("overall", {})
                        
                        return {
                            "uuid": scan_uuid,
                            "url": page_data.get("url"),
                            "domain": page_data.get("domain"),
                            "ip": page_data.get("ip"),
                            "country": page_data.get("country"),
                            "screenshot": scan_result.get("task", {}).get("screenshotURL"),
                            "malicious": overall.get("malicious", False),
                            "tags": verdicts.get("tags", []),
                            "threat_score": overall.get("score", 0)
                        }
                    elif result_response.status_code == 404:
                        # Result not ready yet, wait longer
                        time.sleep(3)
                    else:
                        break
    
    except Exception as e:
        print(f"URLScan API error: {e}")
    
    return None


def check_ip_info(ip_address: str) -> Optional[Dict]:
    """Get IP address information (free: 45 req/min)"""
    try:
        # Validate IP address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip_address):
            return None
        
        url = f"{IP_API_URL}/{ip_address}"
        params = {
            "fields": "status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query"
        }
        
        response = requests.get(url, params=params, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "ip": data.get("query"),
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                    "location": {
                        "lat": data.get("lat"),
                        "lon": data.get("lon")
                    }
                }
    
    except Exception as e:
        print(f"IP-API error: {e}")
    
    return None


def extract_urls_from_content(content: bytes) -> List[str]:
    """Extract URLs from file content"""
    urls = []
    try:
        text = content.decode('utf-8', errors='ignore')
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        found_urls = re.findall(url_pattern, text, re.IGNORECASE)
        urls.extend(found_urls)
    except:
        pass
    
    return urls[:10]  # Limit to 10 URLs


def extract_ips_from_content(content: bytes) -> List[str]:
    """Extract IP addresses from file content"""
    ips = []
    try:
        text = content.decode('utf-8', errors='ignore')
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        found_ips = re.findall(ip_pattern, text)
        ips.extend(found_ips)
    except:
        pass
    
    return list(set(ips))[:10]  # Limit to 10 unique IPs


def analyze_url(url: str) -> Dict:
    """Analyze a URL using external APIs"""
    result = {
        "url": url,
        "urlscan": None,
        "ip_info": None,
        "domain_info": {}
    }
    
    # Parse URL to extract domain and IP
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        
        # Check if domain is an IP address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, domain):
            ip_info = check_ip_info(domain)
            if ip_info:
                result["ip_info"] = ip_info
        else:
            # Try to resolve domain to IP
            try:
                ip_address = socket.gethostbyname(domain)
                ip_info = check_ip_info(ip_address)
                if ip_info:
                    result["ip_info"] = ip_info
                    result["domain_info"]["resolved_ip"] = ip_address
            except:
                pass
        
        result["domain_info"]["domain"] = domain
        
    except Exception as e:
        print(f"URL parsing error: {e}")
    
    # Scan URL with URLScan.io
    urlscan_result = scan_url_with_urlscan(url)
    if urlscan_result:
        result["urlscan"] = urlscan_result
    
    return result


def analyze_with_external_apis(file_path: str, file_content: bytes = None) -> Dict:
    """Run all external API checks"""
    result = {
        "file_hashes": {},
        "virustotal": None,
        "malwarebazaar": None,
        "url_scans": [],
        "ip_info": []
    }
    
    # Calculate file hashes
    hashes = calculate_file_hashes(file_path)
    result["file_hashes"] = hashes
    
    # Check VirusTotal (SHA256)
    if hashes.get("sha256"):
        vt_result = check_virustotal(hashes["sha256"])
        if vt_result:
            result["virustotal"] = vt_result
    
    # Check MalwareBazaar (SHA256)
    if hashes.get("sha256"):
        mb_result = check_malwarebazaar(hashes["sha256"])
        if mb_result:
            result["malwarebazaar"] = mb_result
    
    # Extract and scan URLs if content provided
    if file_content:
        urls = extract_urls_from_content(file_content)
        for url in urls[:3]:  # Limit to 3 URL scans
            url_scan = scan_url_with_urlscan(url)
            if url_scan:
                result["url_scans"].append(url_scan)
        
        # Extract and check IPs
        ips = extract_ips_from_content(file_content)
        for ip in ips[:5]:  # Limit to 5 IP checks
            ip_info = check_ip_info(ip)
            if ip_info:
                result["ip_info"].append(ip_info)
    
    return result

