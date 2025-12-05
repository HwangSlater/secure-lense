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
import zipfile
import math
import collections
import hashlib
import base64

# Optional imports for enhanced analysis
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    try:
        import magic as magic_module
        MAGIC_AVAILABLE = True
    except ImportError:
        MAGIC_AVAILABLE = False
        print("Warning: python-magic not available, file type verification disabled")

try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False
    print("Warning: oletools not available, Office document analysis disabled")

try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("Warning: PyPDF2 not available, PDF analysis disabled")

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    print("Warning: LIEF not available, enhanced PE analysis disabled")

# External API integration
try:
    from external_apis import analyze_with_external_apis
    EXTERNAL_APIS_AVAILABLE = True
except ImportError:
    EXTERNAL_APIS_AVAILABLE = False
    print("Warning: external_apis module not available")

ALLOWED_EXTENSIONS = {'.exe', '.dll', '.pdf', '.docx', '.eml', '.zip'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/securelens_uploads")
SCAN_TIMEOUT = 30

# Korean phishing keywords
PHISHING_KEYWORDS = ["긴급", "계좌 확인", "비밀번호 변경", "당첨", "세금 환급", "배송 확인", "본인 인증"]

# Shellcode patterns
SHELLCODE_PATTERNS = [
    rb'\x90\x90\x90\x90\x90\x90\x90\x90',  # NOP sled (8+ bytes)
    rb'\x90{6,}',  # NOP sled (6+ bytes)
    rb'\xEB\xFE',  # JMP short (infinite loop)
    rb'\xE8\x00\x00\x00\x00',  # CALL
    rb'\x68\x00\x00\x00\x00',  # PUSH
    rb'\x31\xC0',  # XOR EAX, EAX
    rb'\x31\xDB',  # XOR EBX, EBX
    rb'\x31\xC9',  # XOR ECX, ECX
    rb'\x31\xD2',  # XOR EDX, EDX
    rb'\x50\x53\x51\x52',  # PUSH sequence
    rb'\x58\x5B\x59\x5A',  # POP sequence
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
    rb'VirtualAlloc',
    rb'VirtualProtect',
    rb'CreateRemoteThread',
    rb'WriteProcessMemory',
    rb'URLDownloadToFile',
    rb'WinExec',
    rb'ShellExecute',
    rb'CreateService',
    rb'SetWindowsHookEx',
    rb'LoadLibrary',
    rb'GetProcAddress',
    rb'CreateProcess',
    rb'\.onion',
    rb'tor2web',
    rb'pastebin\.com',
    rb'github\.com/[^\s]+\.exe',
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
            # Connect to ClamAV container
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
            try:
                if b'{' in pattern or b'}' in pattern:
                    # Use regex pattern directly
                    matches = list(re.finditer(pattern, content))
                else:
                    # Escape special characters
                    matches = list(re.finditer(re.escape(pattern), content))
                
                for match in matches[:5]:  # Limit to first 5 matches
                    offset = hex(match.start())
                    if b'\x90' in pattern:
                        result["shellcode_patterns"].append(f"NOP sled detected at offset {offset}")
                    elif b'\xEB\xFE' in pattern:
                        result["shellcode_patterns"].append(f"JMP short (infinite loop) detected at offset {offset}")
                    elif b'\xE8' in pattern:
                        result["shellcode_patterns"].append(f"CALL instruction detected at offset {offset}")
                    elif b'\x68' in pattern:
                        result["shellcode_patterns"].append(f"PUSH instruction detected at offset {offset}")
                    elif b'\x31' in pattern:
                        result["shellcode_patterns"].append(f"XOR register instruction detected at offset {offset}")
                    elif b'\x50' in pattern or b'\x58' in pattern:
                        result["shellcode_patterns"].append(f"PUSH/POP sequence detected at offset {offset}")
            except Exception:
                # Skip invalid patterns
                pass
        
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
                packed_section_names = ['.packed', '.upx', '.upx0', '.upx1', '.aspack', '.nspack', '.petite', '.mew']
                
                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    characteristics = section.Characteristics
                    
                    # Check for executable sections with write permission
                    if (characteristics & 0x20000000) and (characteristics & 0x80000000):
                        suspicious_sections.append(f"Section '{section_name}' has both EXECUTE and WRITE permissions")
                    
                    # Check for packed sections
                    if any(packed_name in section_name.lower() for packed_name in packed_section_names):
                        suspicious_sections.append(f"Section '{section_name}' suggests file may be packed")
                
                # Check for suspicious imports
                suspicious_imports = []
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    suspicious_api_patterns = [
                        'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread',
                        'WriteProcessMemory', 'SetWindowsHookEx', 'URLDownloadToFile',
                        'WinExec', 'ShellExecute', 'RegSetValue', 'CreateService'
                    ]
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                        for imp in entry.imports:
                            if imp.name:
                                api_name = imp.name.decode('utf-8', errors='ignore')
                                if any(pattern.lower() in api_name.lower() for pattern in suspicious_api_patterns):
                                    suspicious_imports.append(f"{dll_name}:{api_name}")
                
                # Add suspicious imports to anomalies if found
                if suspicious_imports:
                    suspicious_sections.append(f"Suspicious API imports detected: {', '.join(suspicious_imports[:5])}")
                
                # Check for unusually low section count (potential packed file)
                if len(pe.sections) < 3:
                    suspicious_sections.append(f"Unusually low section count ({len(pe.sections)}), may indicate packing")
                
                result["pe_header_anomalies"] = suspicious_sections
                
            except Exception as e:
                # Not a valid PE file or parsing failed
                pass
        
    except Exception as e:
        print(f"Binary analysis error: {e}")
    
    return result


def calculate_entropy(file_path: str) -> float:
    """Calculate file entropy to detect packing/encryption (0-8, higher = more random)"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if len(data) == 0:
            return 0.0
        
        # Calculate byte frequency
        byte_counts = collections.Counter(data)
        file_size = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / file_size
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    except Exception as e:
        print(f"Entropy calculation error: {e}")
        return 0.0


def verify_file_type(file_path: str, expected_extension: str) -> Dict:
    """Verify actual file type using magic numbers"""
    result = {
        "actual_type": None,
        "extension_match": True,
        "suspicious": False
    }
    
    if not MAGIC_AVAILABLE:
        return result
    
    try:
        mime = magic.Magic(mime=True)
        actual_mime = mime.from_file(file_path)
        result["actual_type"] = actual_mime
        
        # Check if extension matches actual file type
        extension_map = {
            '.exe': ['application/x-dosexec', 'application/x-msdownload', 'application/x-executable'],
            '.dll': ['application/x-dosexec', 'application/x-msdownload'],
            '.pdf': ['application/pdf'],
            '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
            '.zip': ['application/zip', 'application/x-zip-compressed'],
            '.eml': ['message/rfc822', 'text/plain']
        }
        
        expected_mimes = extension_map.get(expected_extension.lower(), [])
        if expected_mimes and actual_mime not in expected_mimes:
            result["extension_match"] = False
            result["suspicious"] = True
        
        # Check for suspicious mismatches
        if expected_extension.lower() in ['.pdf', '.docx', '.zip']:
            if 'executable' in actual_mime.lower() or 'dosexec' in actual_mime.lower():
                result["suspicious"] = True
        
    except Exception as e:
        print(f"File type verification error: {e}")
    
    return result


def analyze_office_document(file_path: str) -> Dict:
    """Analyze Office documents for VBA macros and suspicious content"""
    result = {
        "has_macros": False,
        "macro_count": 0,
        "suspicious_macros": [],
        "auto_exec_macros": False,
        "suspicious_keywords": []
    }
    
    if not OLETOOLS_AVAILABLE:
        return result
    
    try:
        vba_parser = VBA_Parser(file_path)
        
        if vba_parser.detect_vba_macros():
            result["has_macros"] = True
            
            # Analyze macros
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                result["macro_count"] += 1
                
                # Check for auto-exec macros
                auto_exec_patterns = [
                    r'auto_open', r'auto_close', r'workbook_open', r'document_open',
                    r'autoexec', r'autonew', r'autoclose'
                ]
                for pattern in auto_exec_patterns:
                    if re.search(pattern, vba_code, re.IGNORECASE):
                        result["auto_exec_macros"] = True
                        result["suspicious_macros"].append(f"{vba_filename}: Auto-exec macro detected")
                
                # Check for suspicious keywords
                suspicious_vba_keywords = [
                    'shell', 'createobject', 'wscript.shell', 'exec', 'run',
                    'downloadfile', 'urlmon', 'xmlhttp', 'adodb.stream',
                    'regwrite', 'regdelete', 'getobject', 'sendkeys'
                ]
                found_keywords = []
                for keyword in suspicious_vba_keywords:
                    if re.search(rf'\b{keyword}\b', vba_code, re.IGNORECASE):
                        found_keywords.append(keyword)
                
                if found_keywords:
                    result["suspicious_keywords"].extend(found_keywords)
                    result["suspicious_macros"].append(f"{vba_filename}: Suspicious keywords: {', '.join(found_keywords[:3])}")
            
            vba_parser.close()
    
    except Exception as e:
        print(f"Office document analysis error: {e}")
    
    return result


def analyze_pdf(file_path: str) -> Dict:
    """Analyze PDF files for suspicious content"""
    result = {
        "has_javascript": False,
        "has_forms": False,
        "has_actions": False,
        "page_count": 0,
        "suspicious_objects": []
    }
    
    if not PDF_AVAILABLE:
        return result
    
    try:
        with open(file_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            result["page_count"] = len(pdf_reader.pages)
            
            # Check for JavaScript
            if '/JS' in pdf_reader.trailer or '/JavaScript' in pdf_reader.trailer:
                result["has_javascript"] = True
                result["suspicious_objects"].append("JavaScript detected in PDF")
            
            # Check pages for actions
            for i, page in enumerate(pdf_reader.pages[:10]):  # Limit to first 10 pages
                if '/Annots' in page:
                    result["has_actions"] = True
                    result["suspicious_objects"].append(f"Interactive elements in page {i+1}")
                
                if '/AcroForm' in page:
                    result["has_forms"] = True
            
            # Check for embedded files
            if '/EmbeddedFiles' in pdf_reader.trailer:
                result["suspicious_objects"].append("Embedded files detected")
    
    except Exception as e:
        print(f"PDF analysis error: {e}")
    
    return result


def analyze_zip(file_path: str) -> Dict:
    """Analyze ZIP files for suspicious content"""
    result = {
        "file_count": 0,
        "suspicious_files": [],
        "encrypted": False,
        "nested_archives": False,
        "double_extension_files": []
    }
    
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            file_list = zip_ref.namelist()
            result["file_count"] = len(file_list)
            
            for filename in file_list:
                # Check for double extensions
                if re.search(r'\.(pdf|doc|docx|jpg|png|txt)\.(exe|bat|cmd|scr|vbs|js)', filename, re.IGNORECASE):
                    result["double_extension_files"].append(filename)
                    result["suspicious_files"].append(f"Double extension: {filename}")
                
                # Check for executable files
                if filename.lower().endswith(('.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.ps1')):
                    result["suspicious_files"].append(f"Executable file: {filename}")
                
                # Check for nested archives
                if filename.lower().endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
                    result["nested_archives"] = True
                    result["suspicious_files"].append(f"Nested archive: {filename}")
                
                # Check if encrypted
                try:
                    zip_info = zip_ref.getinfo(filename)
                    if zip_info.flag_bits & 0x1:  # Encrypted flag
                        result["encrypted"] = True
                except:
                    pass
    
    except zipfile.BadZipFile:
        result["suspicious_files"].append("Invalid or corrupted ZIP file")
    except Exception as e:
        print(f"ZIP analysis error: {e}")
    
    return result


def calculate_file_hashes(file_path: str) -> Dict:
    """Calculate MD5, SHA1, and SHA256 hashes of a file"""
    result = {
        "md5": None,
        "sha1": None,
        "sha256": None
    }
    
    try:
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)
        
        result["md5"] = hash_md5.hexdigest()
        result["sha1"] = hash_sha1.hexdigest()
        result["sha256"] = hash_sha256.hexdigest()
    except Exception as e:
        print(f"Error calculating file hashes: {e}")
    
    return result


def analyze_file_size(file_path: str) -> Dict:
    """Analyze file size for anomalies"""
    result = {
        "size_bytes": 0,
        "size_mb": 0.0,
        "suspicious": False,
        "anomalies": []
    }
    
    try:
        size = os.path.getsize(file_path)
        result["size_bytes"] = size
        result["size_mb"] = round(size / (1024 * 1024), 2)
        
        # Check for suspicious sizes
        # Too small (less than 1KB) - might be a dropper or incomplete file
        if size < 1024:
            result["suspicious"] = True
            result["anomalies"].append("파일 크기가 매우 작음 (1KB 미만) - 불완전한 파일 또는 드로퍼 가능성")
        
        # Too large (more than 100MB) - might be a data exfiltration or oversized payload
        if size > 100 * 1024 * 1024:
            result["suspicious"] = True
            result["anomalies"].append("파일 크기가 매우 큼 (100MB 초과) - 데이터 유출 또는 과도한 페이로드 가능성")
        
        # Suspiciously small for executable (less than 10KB for .exe/.dll)
        if file_path.lower().endswith(('.exe', '.dll')) and size < 10 * 1024:
            result["suspicious"] = True
            result["anomalies"].append("실행 파일 크기가 비정상적으로 작음 (10KB 미만)")
        
    except Exception as e:
        print(f"Error analyzing file size: {e}")
    
    return result


def analyze_filename_pattern(filename: str) -> Dict:
    """Analyze filename for suspicious patterns"""
    result = {
        "suspicious": False,
        "anomalies": [],
        "patterns_detected": []
    }
    
    try:
        filename_lower = filename.lower()
        
        # Check for double extensions
        if re.search(r'\.(pdf|doc|docx|zip|jpg|png|txt|gif)\.(exe|bat|cmd|scr|vbs|js|ps1)', filename_lower):
            result["suspicious"] = True
            result["anomalies"].append("이중 확장자 발견 - 확장자 위조 시도")
            result["patterns_detected"].append("double_extension")
        
        # Check for suspicious keywords in filename
        suspicious_keywords = [
            'invoice', 'receipt', 'document', 'scan', 'photo', 'image',
            'urgent', 'important', 'readme', 'install', 'update', 'patch',
            'invoice', 'receipt', 'document', 'scan', 'photo', 'image',
            '긴급', '중요', '확인', '인증', '업데이트', '설치'
        ]
        
        found_keywords = []
        for keyword in suspicious_keywords:
            if keyword in filename_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            result["suspicious"] = True
            result["anomalies"].append(f"의심스러운 키워드 발견: {', '.join(found_keywords[:5])}")
            result["patterns_detected"].append("suspicious_keywords")
        
        # Check for random-looking filenames (many random characters)
        if re.search(r'^[a-z0-9]{20,}', filename_lower):
            result["suspicious"] = True
            result["anomalies"].append("랜덤 문자로 구성된 파일명 - 악성코드 생성 파일 가능성")
            result["patterns_detected"].append("random_filename")
        
        # Check for spaces and special characters (common in phishing)
        if filename.count(' ') > 3:
            result["suspicious"] = True
            result["anomalies"].append("과도한 공백 문자 - 피싱 파일명 패턴")
            result["patterns_detected"].append("excessive_spaces")
        
        # Check for Unicode characters (homograph attacks)
        if any(ord(c) > 127 for c in filename):
            result["suspicious"] = True
            result["anomalies"].append("유니코드 문자 포함 - 호모그래프 공격 가능성")
            result["patterns_detected"].append("unicode_characters")
        
    except Exception as e:
        print(f"Error analyzing filename pattern: {e}")
    
    return result


def detect_base64_encoding(file_path: str) -> Dict:
    """Detect Base64 encoded content in file"""
    result = {
        "has_base64": False,
        "base64_strings": [],
        "suspicious": False,
        "anomalies": []
    }
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Base64 pattern: A-Z, a-z, 0-9, +, /, = (padding)
        # Base64 strings are typically longer than 20 characters
        base64_pattern = rb'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.finditer(base64_pattern, content)
        
        base64_strings = []
        for match in islice(matches, 50):  # Limit to 50 matches
            try:
                base64_str = match.group(0).decode('ascii')
                # Try to decode to verify it's valid Base64
                try:
                    decoded = base64.b64decode(base64_str, validate=True)
                    # Only add if decoded data is substantial (more than 10 bytes)
                    if len(decoded) > 10:
                        base64_strings.append({
                            "string": base64_str[:50] + "..." if len(base64_str) > 50 else base64_str,
                            "decoded_size": len(decoded),
                            "offset": hex(match.start())
                        })
                except:
                    # Invalid Base64, skip
                    pass
            except:
                pass
        
        if base64_strings:
            result["has_base64"] = True
            result["base64_strings"] = base64_strings[:10]  # Limit to 10
            
            # Check if there are many Base64 strings (suspicious)
            if len(base64_strings) > 5:
                result["suspicious"] = True
                result["anomalies"].append(f"다수의 Base64 인코딩 문자열 발견 ({len(base64_strings)}개) - 난독화 또는 페이로드 숨김 가능성")
            
            # Check for very long Base64 strings (suspicious)
            long_strings = [s for s in base64_strings if s["decoded_size"] > 1000]
            if long_strings:
                result["suspicious"] = True
                result["anomalies"].append(f"대용량 Base64 인코딩 데이터 발견 (최대 {max(s['decoded_size'] for s in long_strings)} 바이트)")
    
    except Exception as e:
        print(f"Error detecting Base64 encoding: {e}")
    
    return result


def extract_strings_enhanced(file_path: str) -> Dict:
    """Enhanced string extraction with multiple encodings"""
    result = {
        "ascii_strings": [],
        "unicode_strings": [],
        "urls": [],
        "ips": [],
        "email_addresses": []
    }
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Extract ASCII strings (printable, length >= 4)
        ascii_pattern = rb'[\x20-\x7E]{4,}'
        ascii_matches = re.finditer(ascii_pattern, content)
        for match in islice(ascii_matches, 100):  # Limit to 100
            try:
                string = match.group(0).decode('ascii', errors='ignore')
                if len(string) >= 4:
                    result["ascii_strings"].append(string)
            except:
                pass
        
        # Extract Unicode strings (UTF-16 LE)
        unicode_pattern = rb'(?:[\x20-\x7E][\x00]){4,}'
        unicode_matches = re.finditer(unicode_pattern, content)
        for match in islice(unicode_matches, 50):  # Limit to 50
            try:
                string = match.group(0).decode('utf-16-le', errors='ignore')
                if len(string) >= 4:
                    result["unicode_strings"].append(string)
            except:
                pass
        
        # Extract URLs
        url_pattern = rb'https?://[^\x00-\x1F\x7F-\xFF\s<>"{}|\\^`\[\]]+'
        url_matches = re.finditer(url_pattern, content)
        for match in islice(url_matches, 20):
            try:
                url = match.group(0).decode('utf-8', errors='ignore')
                result["urls"].append(url)
            except:
                pass
        
        # Extract IP addresses
        ip_pattern = rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.finditer(ip_pattern, content)
        for match in islice(ip_matches, 20):
            try:
                ip = match.group(0).decode('ascii')
                result["ips"].append(ip)
            except:
                pass
        
        # Extract email addresses
        email_pattern = rb'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        email_matches = re.finditer(email_pattern, content)
        for match in islice(email_matches, 20):
            try:
                email_addr = match.group(0).decode('ascii')
                result["email_addresses"].append(email_addr)
            except:
                pass
    
    except Exception as e:
        print(f"Enhanced string extraction error: {e}")
    
    return result


def analyze_pe_enhanced(file_path: str) -> Dict:
    """Enhanced PE analysis using LIEF"""
    result = {
        "imports": [],
        "exports": [],
        "sections": [],
        "resources": [],
        "suspicious_characteristics": []
    }
    
    if not LIEF_AVAILABLE:
        return result
    
    try:
        binary = lief.parse(file_path)
        if binary is None:
            return result
        
        # Extract imports
        for imported_lib in binary.imports:
            lib_name = imported_lib.name
            for func in imported_lib.entries:
                if func.name:
                    result["imports"].append(f"{lib_name}:{func.name}")
        
        # Extract exports
        for exported_func in binary.exports:
            if exported_func.name:
                result["exports"].append(exported_func.name)
        
        # Analyze sections
        for section in binary.sections:
            section_info = {
                "name": section.name,
                "size": section.size,
                "entropy": section.entropy,
                "characteristics": []
            }
            
            # Check for high entropy (packing indicator)
            if section.entropy > 7.0:
                section_info["characteristics"].append("High entropy (possible packing)")
                result["suspicious_characteristics"].append(f"Section '{section.name}' has high entropy ({section.entropy:.2f})")
            
            # Check for executable + writable sections
            if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE) and \
               section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
                section_info["characteristics"].append("Executable + Writable (suspicious)")
                result["suspicious_characteristics"].append(f"Section '{section.name}' is both executable and writable")
            
            result["sections"].append(section_info)
        
        # Check resources
        if binary.has_resources:
            result["resources"].append("PE resources detected")
    
    except Exception as e:
        print(f"Enhanced PE analysis error: {e}")
    
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
    filename: str,
    external_apis: Optional[Dict] = None,
    entropy: float = 0.0,
    file_type_analysis: Optional[Dict] = None,
    office_analysis: Optional[Dict] = None,
    pdf_analysis: Optional[Dict] = None,
    zip_analysis: Optional[Dict] = None,
    pe_enhanced: Optional[Dict] = None,
    file_size_analysis: Optional[Dict] = None,
    filename_pattern_analysis: Optional[Dict] = None,
    base64_analysis: Optional[Dict] = None
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
    
    # Suspicious strings: +10 (if 3 or more), +15 (if 5 or more)
    suspicious_strings_count = len(binary_analysis.get("suspicious_strings", []))
    if suspicious_strings_count >= 5:
        score += 15
    elif suspicious_strings_count >= 3:
        score += 10
    
    # PE Header anomalies: +15 (if any suspicious sections found)
    if binary_analysis.get("pe_header_anomalies"):
        score += 15
    
    # Enhanced PE analysis (LIEF)
    if pe_enhanced:
        if pe_enhanced.get("suspicious_characteristics"):
            score += min(20, len(pe_enhanced["suspicious_characteristics"]) * 5)
    
    # Entropy analysis (high entropy = possible packing/encryption)
    if entropy > 7.5:
        score += 20
    elif entropy > 7.0:
        score += 15
    elif entropy > 6.5:
        score += 10
    
    # File type mismatch (extension doesn't match actual file type)
    if file_type_analysis and file_type_analysis.get("suspicious"):
        score += 15
    if file_type_analysis and not file_type_analysis.get("extension_match"):
        score += 10
    
    # Office document analysis
    if office_analysis:
        if office_analysis.get("has_macros"):
            score += 15
        if office_analysis.get("auto_exec_macros"):
            score += 20
        if office_analysis.get("suspicious_macros"):
            score += min(15, len(office_analysis["suspicious_macros"]) * 5)
    
    # PDF analysis
    if pdf_analysis:
        if pdf_analysis.get("has_javascript"):
            score += 15
        if pdf_analysis.get("suspicious_objects"):
            score += min(10, len(pdf_analysis["suspicious_objects"]) * 3)
    
    # ZIP analysis
    if zip_analysis:
        if zip_analysis.get("suspicious_files"):
            score += min(15, len(zip_analysis["suspicious_files"]) * 3)
        if zip_analysis.get("encrypted"):
            score += 10
        if zip_analysis.get("nested_archives"):
            score += 10
        if zip_analysis.get("double_extension_files"):
            score += min(15, len(zip_analysis["double_extension_files"]) * 5)
    
    # Email-specific: spear-phishing indicators
    if email_analysis.get("spoofed_sender"):
        score += 10
    if email_analysis.get("phishing_keywords"):
        score += min(20, len(email_analysis["phishing_keywords"]) * 5)
    if email_analysis.get("has_double_extension"):
        score += 10
    if len(email_analysis.get("suspicious_urls", [])) > 3:
        score += 10
    
    # Double extension in filename (now handled by filename_pattern_analysis)
    # This is kept for backward compatibility
    if re.search(r'\.(pdf|doc|docx|zip)\.(exe|bat|cmd)', filename, re.IGNORECASE):
        score += 15
    
    # Filename pattern analysis
    if filename_pattern_analysis and filename_pattern_analysis.get("suspicious"):
        score += min(15, len(filename_pattern_analysis.get("anomalies", [])) * 5)
    
    # File size anomalies
    if file_size_analysis and file_size_analysis.get("suspicious"):
        score += min(10, len(file_size_analysis.get("anomalies", [])) * 5)
    
    # Base64 encoding detection
    if base64_analysis and base64_analysis.get("suspicious"):
        score += min(15, len(base64_analysis.get("anomalies", [])) * 5)
    
    # External API results
    if external_apis:
        # VirusTotal detection (minimum 5 detections required)
        vt_result = external_apis.get("virustotal")
        if vt_result and vt_result.get("detected", 0) >= 5:
            detected_ratio = vt_result["detected"] / max(vt_result.get("total", 1), 1)
            if detected_ratio >= 0.5:  # 50%+ detection
                score += 35
            elif detected_ratio >= 0.2:  # 20%+ detection
                score += 25
            else:  # 5+ detections but < 20%
                score += 15
        
        # MalwareBazaar match
        if external_apis.get("malwarebazaar"):
            score += 20
        
        # URL scans (VirusTotal and URLScan.io)
        url_scans = external_apis.get("url_scans", [])
        for scan in url_scans:
            # VirusTotal URL detection (primary - more reliable, minimum 5 detections required)
            vt_url = scan.get("virustotal")
            if vt_url and isinstance(vt_url, dict) and vt_url.get("detected", 0) >= 5:
                detected_ratio = vt_url["detected"] / max(vt_url.get("total", 1), 1)
                if detected_ratio >= 0.5:  # 50%+ detection
                    score += 30
                elif detected_ratio >= 0.2:  # 20%+ detection
                    score += 20
                else:  # 5+ detections but < 20%
                    score += 15
            # URLScan.io malicious detection (secondary)
            elif scan.get("urlscan", {}).get("malicious", False):
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
    """Main analysis pipeline with enhanced analysis tools"""
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
        "entropy": 0.0,
        "file_type_analysis": {},
        "office_analysis": {},
        "pdf_analysis": {},
        "zip_analysis": {},
        "pe_enhanced": {},
        "strings_enhanced": {},
        "file_hashes": {},
        "file_size_analysis": {},
        "filename_pattern_analysis": {},
        "base64_analysis": {},
        "risk_score": 0,
        "risk_level": "매우 낮음"
    }
    
    ext = Path(original_filename).suffix.lower()
    
    # ClamAV scan
    virus_name, detected = scan_clamav(file_path)
    result["clamav_result"] = virus_name
    result["clamav_detected"] = detected
    
    # YARA scan
    yara_matches = scan_yara(file_path)
    result["yara_matches"] = yara_matches
    
    # Entropy calculation (for packing detection)
    entropy = calculate_entropy(file_path)
    result["entropy"] = round(entropy, 2)
    
    # File type verification
    file_type_analysis = verify_file_type(file_path, ext)
    result["file_type_analysis"] = file_type_analysis
    
    # Binary analysis
    binary_analysis = analyze_binary(file_path)
    result["binary_analysis"] = binary_analysis
    
    # Enhanced PE analysis (for PE files)
    if ext in ['.exe', '.dll']:
        pe_enhanced = analyze_pe_enhanced(file_path)
        result["pe_enhanced"] = pe_enhanced
    else:
        pe_enhanced = {}
    
    # Office document analysis
    if ext in ['.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt']:
        office_analysis = analyze_office_document(file_path)
        result["office_analysis"] = office_analysis
    else:
        office_analysis = {}
    
    # PDF analysis
    if ext == '.pdf':
        pdf_analysis = analyze_pdf(file_path)
        result["pdf_analysis"] = pdf_analysis
    else:
        pdf_analysis = {}
    
    # ZIP analysis
    if ext == '.zip':
        zip_analysis = analyze_zip(file_path)
        result["zip_analysis"] = zip_analysis
    else:
        zip_analysis = {}
    
    # Email analysis (for .eml files)
    email_analysis = {}
    if ext == '.eml':
        email_analysis = analyze_email(file_path)
        result["email_analysis"] = email_analysis
    
    # Enhanced string extraction
    strings_enhanced = extract_strings_enhanced(file_path)
    result["strings_enhanced"] = strings_enhanced
    
    # File hash calculation
    file_hashes = calculate_file_hashes(file_path)
    result["file_hashes"] = file_hashes
    
    # File size analysis
    file_size_analysis = analyze_file_size(file_path)
    result["file_size_analysis"] = file_size_analysis
    
    # Filename pattern analysis
    filename_pattern_analysis = analyze_filename_pattern(original_filename)
    result["filename_pattern_analysis"] = filename_pattern_analysis
    
    # Base64 encoding detection
    base64_analysis = detect_base64_encoding(file_path)
    result["base64_analysis"] = base64_analysis
    
    # External API analysis (async, non-blocking)
    external_apis_result = {}
    if EXTERNAL_APIS_AVAILABLE:
        try:
            # Read file content for URL/IP extraction
            with open(file_path, 'rb') as f:
                file_content = f.read()
            external_apis_result = analyze_with_external_apis(file_path, file_content)
            result["external_apis"] = external_apis_result
        except Exception as e:
            print(f"External API analysis error: {e}")
            result["external_apis"] = {}
    
    # Calculate risk score with all analysis results
    risk_score, risk_level = calculate_risk_score(
        detected,
        yara_matches,
        binary_analysis,
        email_analysis,
        original_filename,
        external_apis_result if external_apis_result else None,
        entropy,
        file_type_analysis,
        office_analysis,
        pdf_analysis,
        zip_analysis,
        pe_enhanced,
        file_size_analysis,
        filename_pattern_analysis,
        base64_analysis
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

