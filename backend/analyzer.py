import os
import re
import uuid
import yara
import pefile
import email
import email.policy
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import socket
import subprocess
import threading
import time
import json
from itertools import islice

ALLOWED_EXTENSIONS = {'.exe', '.dll', '.pdf', '.docx', '.eml', '.zip'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/securelens_uploads")
SCAN_TIMEOUT = 30

# Korean phishing keywords
PHISHING_KEYWORDS = ["긴급", "계좌 확인", "비밀번호 변경", "당첨", "세금 환급", "배송 확인", "본인 인증"]

# Shellcode patterns
SHELLCODE_PATTERNS = [
    rb'\x90\x90\x90\x90\x90\x90\x90\x90',  # NOP sled
    rb'\xEB\xFE',  # JMP short
    rb'\xE8\x00\x00\x00\x00',  # CALL
    rb'\x68\x00\x00\x00\x00',  # PUSH
]

# Suspicious strings patterns
SUSPICIOUS_PATTERNS = [
    rb'cmd\.exe',
    rb'powershell',
    rb'wscript\.exe',
    rb'cscript\.exe',
    rb'reg\s+add',
    rb'net\s+user',
    rb'HKEY_CURRENT_USER',
    rb'HKEY_LOCAL_MACHINE',
    rb'http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
    rb'https?://[^\s<>"{}|\\^`\[\]]+',
]


def ensure_upload_dir():
    """Create upload directory if it doesn't exist"""
    os.makedirs(UPLOAD_DIR, exist_ok=True)


def validate_file(file_path: str, original_filename: str) -> Tuple[bool, Optional[str]]:
    """Validate file size and extension"""
    # Check file size
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        return False, "파일 크기는 50MB를 초과할 수 없습니다."

    # Check extension
    ext = Path(original_filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, "지원하지 않는 파일 형식입니다. (.exe, .dll, .pdf, .docx, .eml만 가능)"

    # Sanitize filename (prevent path traversal)
    if '..' in original_filename or '/' in original_filename or '\\' in original_filename:
        return False, "잘못된 파일명입니다."

    return True, None


def scan_clamav(file_path: str) -> Tuple[Optional[str], bool]:
    """Scan file with ClamAV via socket connection"""
    try:
        # Try to connect to ClamAV daemon
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SCAN_TIMEOUT)
        
        try:
            sock.connect(('clamav', 3310))
            
            # Send SCAN command
            sock.sendall(f'SCAN {file_path}\n'.encode())
            
            # Read response with timeout
            start_time = time.time()
            response = b''
            while time.time() - start_time < SCAN_TIMEOUT:
                try:
                    sock.settimeout(1)
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                    if b'\n' in response:
                        break
                except socket.timeout:
                    continue
            
            sock.close()
            
            response_str = response.decode('utf-8', errors='ignore').strip()
            
            # Parse response: "file_path: VIRUS_NAME FOUND" or "file_path: OK"
            if 'FOUND' in response_str:
                parts = response_str.split(':')
                if len(parts) >= 2:
                    virus_name = parts[1].split('FOUND')[0].strip()
                    return virus_name, True
            
            return None, False
            
        except (socket.timeout, ConnectionRefusedError, OSError):
            # ClamAV not available or timeout - continue without it
            return None, False
        finally:
            sock.close()
            
    except Exception as e:
        # ClamAV scan failed - log but don't fail entire scan
        print(f"ClamAV scan error: {e}")
        return None, False


def load_yara_rules() -> Optional[yara.Rules]:
    """Load YARA rules from rules directory"""
    try:
        rules_dir = Path(__file__).parent / "rules"
        rule_files = list(rules_dir.glob("*.yar"))
        
        if not rule_files:
            return None
        
        # Compile all YARA rules
        rules_content = ""
        for rule_file in rule_files:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rules_content += f.read() + "\n\n"
        
        rules = yara.compile(source=rules_content)
        return rules
    except Exception as e:
        print(f"YARA rules loading error: {e}")
        return None


def scan_yara(file_path: str) -> List[str]:
    """Scan file with YARA rules"""
    matches = []
    try:
        rules = load_yara_rules()
        if not rules:
            return matches
        
        # Set timeout using a thread
        result_container = {"matches": []}
        exception_container = {"error": None}
        
        def scan_thread():
            try:
                file_matches = rules.match(file_path, timeout=SCAN_TIMEOUT)
                result_container["matches"] = [m.rule for m in file_matches]
            except Exception as e:
                exception_container["error"] = e
        
        thread = threading.Thread(target=scan_thread)
        thread.start()
        thread.join(timeout=SCAN_TIMEOUT + 1)
        
        if thread.is_alive():
            # Timeout occurred
            return matches
        
        if exception_container["error"]:
            raise exception_container["error"]
        
        matches = result_container["matches"]
        
    except Exception as e:
        print(f"YARA scan error: {e}")
    
    return matches


def analyze_binary(file_path: str) -> Dict:
    """Analyze binary file for shellcode and suspicious strings"""
    result = {
        "shellcode_patterns": [],
        "suspicious_strings": [],
        "pe_header_anomalies": []
    }
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Detect shellcode patterns
        for pattern in SHELLCODE_PATTERNS:
            matches = list(re.finditer(re.escape(pattern), content))
            for match in matches[:5]:  # Limit to first 5 matches
                offset = hex(match.start())
                if b'\x90\x90' in pattern:
                    result["shellcode_patterns"].append(f"NOP sled detected at offset {offset}")
                elif b'\xEB\xFE' in pattern:
                    result["shellcode_patterns"].append(f"JMP short detected at offset {offset}")
        
        # Detect suspicious strings
        found_strings = set()
        for pattern in SUSPICIOUS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in islice(matches, 10):  # Limit matches using islice
                try:
                    found_string = match.group(0).decode('utf-8', errors='ignore')
                    if len(found_string) > 3:  # Filter very short matches
                        found_strings.add(found_string)
                except:
                    pass
        
        result["suspicious_strings"] = list(found_strings)[:20]  # Limit to 20
        
        # PE Header analysis (for PE files)
        if file_path.lower().endswith(('.exe', '.dll')):
            try:
                pe = pefile.PE(file_path)
                
                # Check for suspicious sections
                suspicious_sections = []
                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    characteristics = section.Characteristics
                    
                    # Check for executable sections with write permission
                    if (characteristics & 0x20000000) and (characteristics & 0x80000000):
                        suspicious_sections.append(f"Section '{section_name}' has both EXECUTE and WRITE permissions")
                
                result["pe_header_anomalies"] = suspicious_sections
                
            except Exception as e:
                # Not a valid PE file or parsing failed
                pass
        
    except Exception as e:
        print(f"Binary analysis error: {e}")
    
    return result


def analyze_email(file_path: str) -> Dict:
    """Analyze email file for spear-phishing indicators"""
    result = {
        "spoofed_sender": False,
        "phishing_keywords": [],
        "suspicious_urls": [],
        "has_double_extension": False,
        "header_analysis": {}
    }
    
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_bytes(f.read(), policy=email.policy.default)
        
        # Extract headers
        from_header = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        return_path = msg.get('Return-Path', '')
        
        result["header_analysis"] = {
            "From": from_header,
            "Reply-To": reply_to,
            "Return-Path": return_path
        }
        
        # Check for sender spoofing
        if reply_to and from_header:
            # Extract email addresses
            from_email = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', from_header, re.IGNORECASE)
            reply_email = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', reply_to, re.IGNORECASE)
            
            if from_email and reply_email:
                if from_email.group(0).lower() != reply_email.group(0).lower():
                    result["spoofed_sender"] = True
        
        # Extract email body content
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" or content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text += payload.decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                pass
        
        # Check for phishing keywords
        for keyword in PHISHING_KEYWORDS:
            if keyword in body_text:
                result["phishing_keywords"].append(keyword)
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, body_text, re.IGNORECASE)
        
        # Check for homograph attacks (basic check)
        suspicious_urls = []
        for url in urls:
            # Check for mixed scripts (basic heuristic)
            if any(ord(c) > 127 for c in url):
                suspicious_urls.append(f"{url} (possible homograph)")
            else:
                suspicious_urls.append(url)
        
        result["suspicious_urls"] = suspicious_urls[:10]  # Limit to 10
        
        # Check attachments for double extensions
        if msg.is_multipart():
            for part in msg.walk():
                filename = part.get_filename()
                if filename:
                    # Check for double extension
                    if re.search(r'\.(pdf|doc|docx|zip|jpg|png)\.(exe|bat|cmd|scr)', filename, re.IGNORECASE):
                        result["has_double_extension"] = True
        
    except Exception as e:
        print(f"Email analysis error: {e}")
    
    return result


def calculate_risk_score(
    clamav_detected: bool,
    yara_matches: List[str],
    binary_analysis: Dict,
    email_analysis: Dict,
    filename: str
) -> Tuple[int, str]:
    """Calculate risk score (0-100) and risk level"""
    score = 0
    
    # ClamAV detection: +40
    if clamav_detected:
        score += 40
    
    # YARA matches: +30 (up to 30)
    if yara_matches:
        score += min(30, len(yara_matches) * 10)
    
    # Shellcode patterns: +20
    if binary_analysis.get("shellcode_patterns"):
        score += 20
    
    # Suspicious strings: +10 (if more than 5)
    if len(binary_analysis.get("suspicious_strings", [])) > 5:
        score += 10
    
    # Email-specific: spear-phishing indicators
    if email_analysis.get("spoofed_sender"):
        score += 10
    if email_analysis.get("phishing_keywords"):
        score += min(20, len(email_analysis["phishing_keywords"]) * 5)
    if email_analysis.get("has_double_extension"):
        score += 10
    if len(email_analysis.get("suspicious_urls", [])) > 3:
        score += 10
    
    # Double extension in filename
    if re.search(r'\.(pdf|doc|docx|zip)\.(exe|bat|cmd)', filename, re.IGNORECASE):
        score += 15
    
    # Cap at 100
    score = min(score, 100)
    
    # Determine risk level (Korean)
    if score <= 20:
        level = "매우 낮음"
    elif score <= 40:
        level = "낮음"
    elif score <= 60:
        level = "보통"
    elif score <= 80:
        level = "높음"
    else:
        level = "매우 높음"
    
    return score, level


def analyze_file(file_path: str, original_filename: str) -> Dict:
    """Main analysis pipeline"""
    ensure_upload_dir()
    
    # Validate file
    is_valid, error_msg = validate_file(file_path, original_filename)
    if not is_valid:
        raise ValueError(error_msg)
    
    # Initialize result structure
    result = {
        "filename": original_filename,
        "clamav_result": None,
        "clamav_detected": False,
        "yara_matches": [],
        "binary_analysis": {},
        "email_analysis": {},
        "risk_score": 0,
        "risk_level": "매우 낮음"
    }
    
    # ClamAV scan
    virus_name, detected = scan_clamav(file_path)
    result["clamav_result"] = virus_name
    result["clamav_detected"] = detected
    
    # YARA scan
    yara_matches = scan_yara(file_path)
    result["yara_matches"] = yara_matches
    
    # Binary analysis
    binary_analysis = analyze_binary(file_path)
    result["binary_analysis"] = binary_analysis
    
    # Email analysis (for .eml files)
    email_analysis = {}
    if original_filename.lower().endswith('.eml'):
        email_analysis = analyze_email(file_path)
        result["email_analysis"] = email_analysis
    
    # Calculate risk score
    risk_score, risk_level = calculate_risk_score(
        detected,
        yara_matches,
        binary_analysis,
        email_analysis,
        original_filename
    )
    result["risk_score"] = risk_score
    result["risk_level"] = risk_level
    
    return result


def schedule_file_deletion(file_path: str, delay_hours: int = 1):
    """Schedule file deletion after delay"""
    def delete_file():
        time.sleep(delay_hours * 3600)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Deleted file: {file_path}")
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")
    
    thread = threading.Thread(target=delete_file, daemon=True)
    thread.start()

