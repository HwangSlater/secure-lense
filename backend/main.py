from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, Dict, List
import os
import uuid
import json
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

from models import User, Analysis, CreditPurchase, get_db, init_db, pwd_context
from auth import create_access_token, get_current_user, ACCESS_TOKEN_EXPIRE_MINUTES
from analyzer import analyze_file, UPLOAD_DIR, ensure_upload_dir, schedule_file_deletion
import google.generativeai as genai

# External API integration
try:
    from external_apis import analyze_url
    EXTERNAL_APIS_AVAILABLE = True
except ImportError:
    EXTERNAL_APIS_AVAILABLE = False
    print("Warning: external_apis module not available")

app = FastAPI(title="SecureLens API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting storage
upload_counts = defaultdict(list)
MAX_UPLOADS_PER_HOUR = int(os.getenv("MAX_UPLOADS_PER_HOUR", "10"))

# Initialize Gemini
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Initialize database on startup
@app.on_event("startup")
def startup_event():
    init_db()
    ensure_upload_dir()


# Pydantic models
class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str
    credits: int


class FileUploadResponse(BaseModel):
    scan_id: str
    filename: str
    risk_score: int
    risk_level: str
    clamav_result: Optional[str]
    yara_matches: List[str]
    shellcode_patterns: List[str]
    suspicious_strings: List[str]
    spearphishing_indicators: Optional[Dict]
    external_apis: Optional[Dict] = None
    file_deleted_at: str


class AIAnalysisRequest(BaseModel):
    scan_id: str
    email_subject: Optional[str] = None  # 선택사항: 이메일 제목
    email_content: Optional[str] = None  # 선택사항: 이메일 내용


class AIAnalysisResponse(BaseModel):
    analysis: str
    credits_used: int
    remaining_credits: int


class CreditChargeRequest(BaseModel):
    amount: int


class CreditChargeResponse(BaseModel):
    success: bool
    new_balance: int
    message: str


class CreditPurchaseHistoryItem(BaseModel):
    purchased_at: str
    amount: int
    balance_after: int


class AnalysisDetailResponse(BaseModel):
    scan_id: str
    filename: Optional[str]  # Can be None for URL analysis (though we use URL as filename now)
    risk_score: int
    risk_level: str
    clamav_result: Optional[str]
    yara_matches: List[str]
    shellcode_patterns: List[str]
    suspicious_strings: List[str]
    spearphishing_indicators: Optional[Dict] = None
    external_apis: Optional[Dict] = None
    ai_analysis: Optional[str] = None
    file_deleted_at: str
    uploaded_at: str
    # Enhanced analysis fields
    entropy: Optional[float] = None
    file_type_analysis: Optional[Dict] = None
    office_analysis: Optional[Dict] = None
    pdf_analysis: Optional[Dict] = None
    zip_analysis: Optional[Dict] = None
    pe_enhanced: Optional[Dict] = None
    strings_enhanced: Optional[Dict] = None
    file_hashes: Optional[Dict] = None
    file_size_analysis: Optional[Dict] = None
    filename_pattern_analysis: Optional[Dict] = None
    base64_analysis: Optional[Dict] = None
    # URL analysis fields
    url: Optional[str] = None
    urlscan: Optional[Dict] = None
    ip_info: Optional[Dict] = None
    domain_info: Optional[Dict] = None
    analyzed_at: Optional[str] = None
    url_analysis_result: Optional[Dict] = None


class URLAnalysisRequest(BaseModel):
    url: str


class URLAnalysisResponse(BaseModel):
    scan_id: str
    url: str
    risk_score: int
    risk_level: str
    urlscan: Optional[Dict] = None
    ip_info: Optional[Dict] = None
    domain_info: Optional[Dict] = None
    analyzed_at: str


# Note: Analysis results and credit purchase history are now stored in database


# Rate limiting helper
def check_rate_limit(client_ip: str) -> bool:
    """Check if client has exceeded rate limit"""
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=1)
    
    # Clean old entries
    upload_counts[client_ip] = [ts for ts in upload_counts[client_ip] if ts > cutoff]
    
    # Check limit
    if len(upload_counts[client_ip]) >= MAX_UPLOADS_PER_HOUR:
        return False
    
    # Add current upload
    upload_counts[client_ip].append(now)
    return True


# Authentication endpoints
@app.post("/auth/login", response_model=LoginResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not user.verify_password(form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="아이디 또는 비밀번호가 올바르지 않습니다."
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        username=user.username,
        role=user.role,
        credits=user.credits
    )


@app.get("/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "role": current_user.role,
        "credits": current_user.credits
    }


# File upload and analysis endpoint
@app.post("/files/upload", response_model=FileUploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db)
):
    # Rate limiting
    client_ip = request.client.host if request else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="시간당 업로드 제한(10개)을 초과했습니다. 1시간 후 다시 시도해주세요.",
            headers={"Retry-After": "3600"}
        )
    
    # Generate unique filename
    file_id = str(uuid.uuid4())
    file_ext = Path(file.filename).suffix
    stored_filename = f"{file_id}{file_ext}"
    file_path = os.path.join(UPLOAD_DIR, stored_filename)
    
    try:
        # Save uploaded file
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # Analyze file
        analysis_result = analyze_file(file_path, file.filename)
        
        # Prepare response
        scan_id = file_id
        
        # Format response
        response_data = {
            "scan_id": scan_id,
            "filename": file.filename,
            "risk_score": analysis_result["risk_score"],
            "risk_level": analysis_result["risk_level"],
            "clamav_result": analysis_result.get("clamav_result"),
            "yara_matches": analysis_result.get("yara_matches", []),
            "shellcode_patterns": analysis_result.get("binary_analysis", {}).get("shellcode_patterns", []),
            "suspicious_strings": analysis_result.get("binary_analysis", {}).get("suspicious_strings", []),
            "spearphishing_indicators": None,
            "external_apis": analysis_result.get("external_apis", {}),
            "file_deleted_at": (datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z"
        }
        
        # Add email-specific indicators
        if analysis_result.get("email_analysis"):
            email_analysis = analysis_result["email_analysis"]
            response_data["spearphishing_indicators"] = {
                "spoofed_sender": email_analysis.get("spoofed_sender", False),
                "phishing_keywords": email_analysis.get("phishing_keywords", []),
                "suspicious_urls": email_analysis.get("suspicious_urls", []),
                "has_double_extension": email_analysis.get("has_double_extension", False),
                "header_analysis": email_analysis.get("header_analysis", {})
            }
        
        # Store analysis result in database
        db_analysis = Analysis(
            scan_id=scan_id,
            user_id=current_user.id,
            filename=file.filename,
            analysis_data=analysis_result,
            risk_score=analysis_result["risk_score"],
            risk_level=analysis_result["risk_level"],
            uploaded_at=datetime.utcnow()
        )
        db.add(db_analysis)
        db.commit()
        db.refresh(db_analysis)
        
        # Schedule file deletion
        schedule_file_deletion(file_path, delay_hours=1)
        
        return FileUploadResponse(**response_data)
        
    except ValueError as e:
        # Validation error
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        # Other errors
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"파일 분석 중 오류가 발생했습니다: {str(e)}"
        )


# URL analysis endpoint
@app.post("/url/analyze", response_model=URLAnalysisResponse)
async def analyze_url_endpoint(
    request_body: URLAnalysisRequest,
    http_request: Request = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Analyze a URL using external APIs"""
    if not EXTERNAL_APIS_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="URL 분석 기능이 현재 사용할 수 없습니다."
        )
    
    # Rate limiting
    client_ip = http_request.client.host if http_request else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="시간당 분석 제한(10개)을 초과했습니다. 1시간 후 다시 시도해주세요.",
            headers={"Retry-After": "3600"}
        )
    
    # Normalize URL (add http:// if missing)
    url = request_body.url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Analyze URL using external APIs
        url_analysis_result = analyze_url(url)
        
        # Calculate risk score based on VirusTotal (primary) and URLScan.io (secondary) results
        risk_score = 0
        
        # VirusTotal URL scan results (primary - more reliable for malicious detection)
        if url_analysis_result.get('virustotal'):
            vt_result = url_analysis_result['virustotal']
            if isinstance(vt_result, dict) and vt_result.get('detected', 0) > 0:
                detected_ratio = vt_result['detected'] / max(vt_result.get('total', 1), 1)
                if detected_ratio >= 0.5:  # 50%+ detection
                    risk_score = min(100, 80 + int(detected_ratio * 20))
                elif detected_ratio >= 0.2:  # 20%+ detection
                    risk_score = min(80, 60 + int(detected_ratio * 20))
                else:  # Any detection
                    risk_score = min(60, 40 + int(detected_ratio * 20))
        
        # URLScan.io results (secondary - for behavior analysis)
        if url_analysis_result.get('urlscan') and risk_score < 70:
            urlscan = url_analysis_result['urlscan']
            if isinstance(urlscan, dict):
                # Check if URLScan.io detected it as malicious
                if urlscan.get('malicious'):
                    threat_score = urlscan.get('threat_score', 0) or 0
                    risk_score = max(risk_score, min(100, 70 + threat_score))
                else:
                    # Check threat score (0-10 scale)
                    threat_score = urlscan.get('threat_score', 0) or 0
                    if threat_score > 0:
                        risk_score = max(risk_score, min(70, threat_score * 7))  # Convert 0-10 to 0-70
        
        # Determine risk level
        if risk_score >= 86:
            risk_level = "매우 높음"
        elif risk_score >= 71:
            risk_level = "높음"
        elif risk_score >= 51:
            risk_level = "보통"
        elif risk_score >= 31:
            risk_level = "낮음"
        else:
            risk_level = "매우 낮음"
        
        # Generate scan_id
        scan_id = str(uuid.uuid4())
        
        # Prepare analysis data for database
        analysis_data = {
            "url": url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "url_analysis_result": url_analysis_result,
            "virustotal_result": url_analysis_result.get('virustotal'),
            "urlscan_result": url_analysis_result.get('urlscan'),
            "ip_info": url_analysis_result.get('ip_info'),
            "domain_info": url_analysis_result.get('domain_info', {})
        }
        
        # Store analysis result in database
        # For URL analysis, use the URL as filename for consistency
        db_analysis = Analysis(
            scan_id=scan_id,
            user_id=current_user.id,
            filename=url,  # Use URL as filename for URL analysis
            analysis_data=analysis_data,
            risk_score=risk_score,
            risk_level=risk_level,
            uploaded_at=datetime.utcnow()
        )
        db.add(db_analysis)
        db.commit()
        db.refresh(db_analysis)
        
        # Prepare response (urlscan field name matches URLAnalysisResponse model)
        return URLAnalysisResponse(
            scan_id=scan_id,
            url=url,
            risk_score=risk_score,
            risk_level=risk_level,
            urlscan=url_analysis_result.get('urlscan'),
            ip_info=url_analysis_result.get('ip_info'),
            domain_info=url_analysis_result.get('domain_info', {}),
            analyzed_at=datetime.utcnow().isoformat() + "Z"
        )
        
    except Exception as e:
        import traceback
        print(f"URL analysis error: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL 분석 중 오류가 발생했습니다: {str(e)}"
        )


# AI analysis endpoint
@app.post("/analysis/ai", response_model=AIAnalysisResponse)
async def ai_analysis(
    request: AIAnalysisRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan_id = request.scan_id
    
    # Check if analysis result exists in database
    db_analysis = db.query(Analysis).filter(Analysis.scan_id == scan_id).first()
    if not db_analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="분석 결과를 찾을 수 없습니다."
        )
    
    # Check if user owns this analysis
    if db_analysis.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="이 분석 결과에 접근할 권한이 없습니다."
        )
    
    # Check if AI analysis already exists
    if db_analysis.ai_analysis:
        return AIAnalysisResponse(
            analysis=db_analysis.ai_analysis,
            credits_used=0,
            remaining_credits=current_user.credits
        )
    
    analysis_data = db_analysis.analysis_data
    filename = db_analysis.filename
    
    # Check credits (unless admin) - but don't deduct yet
    credits_used = 0
    if current_user.role != "ADMIN":
        if current_user.credits <= 0:
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail="AI 분석을 사용하려면 분석 티켓이 필요합니다. 충전하기에서 티켓을 구매해주세요."
            )
    
    # Prepare external APIs information for prompt
    external_apis_info = ""
    if analysis_data.get('external_apis'):
        ext_apis = analysis_data['external_apis']
        external_apis_info = "\n- 외부 위협 인텔리전스:\n"
        
        # File hashes
        if ext_apis.get('file_hashes'):
            hashes = ext_apis['file_hashes']
            external_apis_info += f"  - 파일 해시 (MD5: {hashes.get('md5', 'N/A')[:16]}..., SHA256: {hashes.get('sha256', 'N/A')[:32]}...)\n"
        
        # VirusTotal results
        if ext_apis.get('virustotal'):
            vt = ext_apis['virustotal']
            if vt.get('detected'):
                external_apis_info += f"  - VirusTotal: {vt.get('positives', 0)}/{vt.get('total', 0)}개 백신 엔진에서 악성코드 탐지\n"
                if vt.get('scans'):
                    detected_by = [name for name, result in vt['scans'].items() if result.get('detected')]
                    if detected_by:
                        external_apis_info += f"    탐지한 백신: {', '.join(detected_by[:5])}{' 등' if len(detected_by) > 5 else ''}\n"
            else:
                external_apis_info += "  - VirusTotal: 악성코드 탐지 없음\n"
        
        # MalwareBazaar results
        if ext_apis.get('malwarebazaar'):
            mb = ext_apis['malwarebazaar']
            if mb.get('found'):
                external_apis_info += f"  - MalwareBazaar: 악성코드 샘플로 확인됨\n"
                if mb.get('malware_family'):
                    external_apis_info += f"    악성코드 패밀리: {mb.get('malware_family')}\n"
                if mb.get('signature'):
                    external_apis_info += f"    시그니처: {mb.get('signature')}\n"
            else:
                external_apis_info += "  - MalwareBazaar: 알려진 악성코드 샘플 아님\n"
        
        # URL scan results (if any URLs were found in the file)
        if ext_apis.get('url_scans'):
            url_scans = ext_apis['url_scans']
            if url_scans:
                external_apis_info += f"  - URL 스캔 결과: {len(url_scans)}개 URL 분석됨\n"
                for i, url_scan in enumerate(url_scans[:3], 1):  # 최대 3개만 표시
                    if url_scan.get('urlscan_result'):
                        urlscan = url_scan['urlscan_result']
                        if urlscan.get('verdicts', {}).get('overall', {}).get('malicious'):
                            external_apis_info += f"    URL {i}: 악성으로 판단됨 (위협 점수: {urlscan.get('verdicts', {}).get('overall', {}).get('score', 'N/A')})\n"
    
    # Prepare email subject/content info if provided
    email_info = ""
    if request.email_subject or request.email_content:
        email_info = "\n- 이메일 정보 (사용자 제공):\n"
        if request.email_subject:
            email_info += f"  - 제목: {request.email_subject}\n"
        if request.email_content:
            # 내용이 너무 길면 일부만 표시
            content_preview = request.email_content[:500] + ("..." if len(request.email_content) > 500 else "")
            email_info += f"  - 내용: {content_preview}\n"
    
    # Prepare enhanced analysis information
    enhanced_analysis_info = ""
    
    # Entropy analysis
    entropy = analysis_data.get('entropy')
    if entropy:
        enhanced_analysis_info += f"\n- 파일 엔트로피: {entropy:.2f}/8.0\n"
        if entropy > 7.5:
            enhanced_analysis_info += "  → 매우 높은 엔트로피: 파일이 암호화되었거나 패킹되었을 가능성이 매우 높습니다.\n"
        elif entropy > 7.0:
            enhanced_analysis_info += "  → 높은 엔트로피: 파일이 패킹되었거나 압축되었을 가능성이 있습니다.\n"
        elif entropy > 6.5:
            enhanced_analysis_info += "  → 중간 엔트로피: 일부 패킹 또는 압축 가능성.\n"
        else:
            enhanced_analysis_info += "  → 정상적인 엔트로피 범위.\n"
    
    # File type verification
    file_type_analysis = analysis_data.get('file_type_analysis')
    if file_type_analysis:
        actual_type = file_type_analysis.get('actual_type')
        extension_match = file_type_analysis.get('extension_match')
        suspicious = file_type_analysis.get('suspicious')
        if actual_type:
            enhanced_analysis_info += f"\n- 실제 파일 타입: {actual_type}\n"
            if not extension_match:
                enhanced_analysis_info += "  → 경고: 파일 확장자와 실제 파일 타입이 일치하지 않습니다. 확장자 위조 가능성이 있습니다.\n"
            if suspicious:
                enhanced_analysis_info += "  → 경고: 의심스러운 파일 타입 불일치가 감지되었습니다.\n"
    
    # Office document analysis
    office_analysis = analysis_data.get('office_analysis')
    if office_analysis:
        enhanced_analysis_info += "\n- Office 문서 분석:\n"
        if office_analysis.get('has_macros'):
            enhanced_analysis_info += f"  → VBA 매크로 발견: {office_analysis.get('macro_count', 0)}개 매크로\n"
            if office_analysis.get('auto_exec_macros'):
                enhanced_analysis_info += "  → 경고: 자동 실행 매크로가 발견되었습니다. 매우 위험합니다.\n"
            suspicious_macros = office_analysis.get('suspicious_macros', [])
            if suspicious_macros:
                enhanced_analysis_info += f"  → 의심스러운 매크로: {len(suspicious_macros)}개\n"
                for macro in suspicious_macros[:3]:
                    enhanced_analysis_info += f"    - {macro}\n"
            suspicious_keywords = office_analysis.get('suspicious_keywords', [])
            if suspicious_keywords:
                enhanced_analysis_info += f"  → 의심스러운 VBA 키워드: {', '.join(set(suspicious_keywords[:5]))}\n"
        else:
            enhanced_analysis_info += "  → 매크로 없음\n"
    
    # PDF analysis
    pdf_analysis = analysis_data.get('pdf_analysis')
    if pdf_analysis:
        enhanced_analysis_info += "\n- PDF 분석:\n"
        enhanced_analysis_info += f"  → 페이지 수: {pdf_analysis.get('page_count', 0)}\n"
        if pdf_analysis.get('has_javascript'):
            enhanced_analysis_info += "  → 경고: JavaScript가 포함되어 있습니다. 악성 PDF의 일반적인 특징입니다.\n"
        if pdf_analysis.get('has_actions'):
            enhanced_analysis_info += "  → 경고: 인터랙티브 요소(액션)가 포함되어 있습니다.\n"
        if pdf_analysis.get('has_forms'):
            enhanced_analysis_info += "  → 폼이 포함되어 있습니다.\n"
        suspicious_objects = pdf_analysis.get('suspicious_objects', [])
        if suspicious_objects:
            enhanced_analysis_info += f"  → 의심스러운 객체: {len(suspicious_objects)}개\n"
            for obj in suspicious_objects[:3]:
                enhanced_analysis_info += f"    - {obj}\n"
    
    # ZIP analysis
    zip_analysis = analysis_data.get('zip_analysis')
    if zip_analysis:
        enhanced_analysis_info += "\n- ZIP 파일 분석:\n"
        enhanced_analysis_info += f"  → 내부 파일 수: {zip_analysis.get('file_count', 0)}\n"
        if zip_analysis.get('encrypted'):
            enhanced_analysis_info += "  → 경고: 암호화된 파일이 포함되어 있습니다.\n"
        if zip_analysis.get('nested_archives'):
            enhanced_analysis_info += "  → 경고: 중첩된 아카이브 파일이 발견되었습니다.\n"
        double_ext_files = zip_analysis.get('double_extension_files', [])
        if double_ext_files:
            enhanced_analysis_info += f"  → 경고: 이중 확장자 파일 {len(double_ext_files)}개 발견\n"
            for file in double_ext_files[:3]:
                enhanced_analysis_info += f"    - {file}\n"
        suspicious_files = zip_analysis.get('suspicious_files', [])
        if suspicious_files:
            enhanced_analysis_info += f"  → 의심스러운 파일: {len(suspicious_files)}개\n"
            for file in suspicious_files[:5]:
                enhanced_analysis_info += f"    - {file}\n"
    
    # Enhanced PE analysis
    pe_enhanced = analysis_data.get('pe_enhanced')
    if pe_enhanced:
        enhanced_analysis_info += "\n- PE 파일 상세 분석:\n"
        suspicious_chars = pe_enhanced.get('suspicious_characteristics', [])
        if suspicious_chars:
            enhanced_analysis_info += f"  → 의심스러운 특성: {len(suspicious_chars)}개 발견\n"
            for char in suspicious_chars[:5]:
                enhanced_analysis_info += f"    - {char}\n"
        sections = pe_enhanced.get('sections', [])
        if sections:
            high_entropy_sections = [s for s in sections if s.get('entropy', 0) > 7.0]
            if high_entropy_sections:
                enhanced_analysis_info += f"  → 고엔트로피 섹션: {len(high_entropy_sections)}개 (패킹 가능성)\n"
        imports = pe_enhanced.get('imports', [])
        if imports:
            enhanced_analysis_info += f"  → 임포트된 API: {len(imports)}개\n"
            # Show suspicious imports
            suspicious_imports = [imp for imp in imports[:10] if any(keyword in imp.lower() for keyword in ['virtualalloc', 'createprocess', 'urlmon', 'wininet', 'shell32'])]
            if suspicious_imports:
                enhanced_analysis_info += f"    의심스러운 API: {', '.join(suspicious_imports[:5])}\n"
    
    # Enhanced strings extraction
    strings_enhanced = analysis_data.get('strings_enhanced')
    if strings_enhanced:
        enhanced_analysis_info += "\n- 추출된 문자열 분석:\n"
        urls = strings_enhanced.get('urls', [])
        if urls:
            enhanced_analysis_info += f"  → 발견된 URL: {len(urls)}개\n"
            for url in urls[:5]:
                enhanced_analysis_info += f"    - {url}\n"
        ips = strings_enhanced.get('ips', [])
        if ips:
            enhanced_analysis_info += f"  → 발견된 IP 주소: {len(set(ips))}개 (중복 제거)\n"
            for ip in list(set(ips))[:5]:
                enhanced_analysis_info += f"    - {ip}\n"
        emails = strings_enhanced.get('email_addresses', [])
        if emails:
            enhanced_analysis_info += f"  → 발견된 이메일 주소: {len(set(emails))}개\n"
            for email in list(set(emails))[:3]:
                enhanced_analysis_info += f"    - {email}\n"
    
    # PE Header anomalies
    binary_analysis = analysis_data.get('binary_analysis', {})
    pe_anomalies = binary_analysis.get('pe_header_anomalies', [])
    if pe_anomalies:
        enhanced_analysis_info += "\n- PE 헤더 이상:\n"
        for anomaly in pe_anomalies[:5]:
            enhanced_analysis_info += f"  → {anomaly}\n"
    
    # Prepare Gemini prompt (Korean, no emojis)
    prompt = f"""다음 분석 결과를 바탕으로 보안 분석 보고서를 작성해주세요. 인사말이나 소개 문구 없이 바로 내용부터 시작하세요.

**분석 결과:**

- 파일명: {filename}
- 위험도 점수: {analysis_data['risk_score']}/100
- 위험도 등급: {analysis_data['risk_level']}
- ClamAV 탐지: {analysis_data.get('clamav_result', '없음')}
- YARA 탐지 규칙: {', '.join(analysis_data.get('yara_matches', [])) if analysis_data.get('yara_matches') else '없음'}
- 쉘코드 패턴: {', '.join(analysis_data.get('binary_analysis', {}).get('shellcode_patterns', [])) if analysis_data.get('binary_analysis', {}).get('shellcode_patterns') else '없음'}
- 의심스러운 문자열: {', '.join(analysis_data.get('binary_analysis', {}).get('suspicious_strings', [])[:10]) if analysis_data.get('binary_analysis', {}).get('suspicious_strings') else '없음'}
- 스피어피싱 지표: {json.dumps(analysis_data.get('email_analysis', {}), ensure_ascii=False, indent=2) if analysis_data.get('email_analysis') else '없음'}{external_apis_info}{email_info}{enhanced_analysis_info}

**작업:**

위 분석 결과를 바탕으로 다음 형식으로 상세하고 구체적인 분석을 제공해주세요. 인사말, 소개 문구, "안녕하세요" 같은 표현은 절대 사용하지 마세요. 바로 "## 위험도 평가" 섹션부터 시작하세요.

## 위험도 평가

{analysis_data['risk_level']} - 위험도 점수 {analysis_data['risk_score']}/100에 대한 상세 평가

## 3줄 요약

1. 이 파일의 정체가 무엇인지 (구체적으로)
2. 어떤 위험이 있는지 (실제로 발생할 수 있는 피해)
3. 왜 위험한지 (기술적 근거)

## 스피어피싱 가능성

이 파일이 스피어피싱 공격의 일부일 확률을 0-100%로 평가하고 근거를 제시해주세요.

## 발견된 위협 요소

다음 항목들을 각각 상세히 분석해주세요:

1. **ClamAV 탐지 결과**: 바이러스 시그니처 탐지의 의미와 신뢰도
2. **YARA 규칙 매칭**: 어떤 악성코드 패턴이 매칭되었는지, 그 패턴의 의미
3. **쉘코드 패턴**: 발견된 쉘코드 패턴의 종류와 위험성
4. **의심스러운 문자열**: 발견된 문자열들이 어떤 공격 기법을 나타내는지
5. **엔트로피 분석**: 파일이 패킹되었는지, 암호화되었는지 여부와 그 의미
6. **파일 타입 검증**: 확장자 위조 여부와 실제 파일 타입의 의미
7. **Office 문서 분석**: VBA 매크로의 위험성, 자동 실행 매크로의 의미, 발견된 의심스러운 키워드 분석
8. **PDF 분석**: JavaScript 포함 여부, 인터랙티브 요소의 위험성
9. **ZIP 분석**: 내부 파일들의 위험성, 이중 확장자 파일의 의미, 암호화/중첩 아카이브의 의도
10. **PE 강화 분석**: 고엔트로피 섹션의 의미, 의심스러운 API 임포트 분석, 섹션 특성 이상 분석
11. **추출된 문자열**: 발견된 URL, IP 주소, 이메일 주소의 위험성 평가
12. **PE 헤더 이상**: 발견된 이상 사항들의 의미와 위험성
13. **스피어피싱 지표**: 이메일 분석 결과의 의미와 공격 유형 판단
14. **외부 위협 인텔리전스**: VirusTotal, MalwareBazaar 등의 결과 해석과 신뢰도 평가

## 대응 방법

1. 즉시 해야 할 조치 (구체적인 단계)
2. 예방을 위한 조치 (장기적 대응)

## 유사 공격 사례

실제 발생했던 유사한 공격 사례 1개를 간단히 소개해주세요.

**중요:**
- 인사말, 소개 문구, "안녕하세요", "의뢰하신", "설명해 드리겠습니다" 같은 표현 절대 사용 금지
- 바로 "## 위험도 평가" 섹션부터 시작
- 전문 용어 사용 시 괄호로 쉬운 설명 추가 (예: "쉘코드(악성 명령어)")
- 위험도를 과장하거나 축소하지 말 것
- 구체적인 증거 기반으로만 설명
- 모든 설명은 한국어로 작성
- 이모티콘 사용 금지
- 일반적인 설명이 아닌 이 파일에 특화된 구체적인 분석 제공
- 모든 섹션을 완전히 작성하고 내용이 잘리지 않도록 주의
"""
    
    try:
        # Call Gemini API
        if not GEMINI_API_KEY:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI 분석 서비스가 설정되지 않았습니다."
            )
        
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(
            prompt,
            generation_config={
                'temperature': 0.7,
                'max_output_tokens': 8192,  # 내용이 잘리지 않도록 토큰 수 대폭 증가
            }
        )
        
        # Safely extract text from response
        if not response:
            raise ValueError("Gemini API returned empty response")
        
        # Try to get text from response
        try:
            analysis_text = response.text
        except AttributeError:
            # Fallback: try to get text from candidates
            if hasattr(response, 'candidates') and response.candidates:
                if hasattr(response.candidates[0], 'content') and response.candidates[0].content:
                    if hasattr(response.candidates[0].content, 'parts') and response.candidates[0].content.parts:
                        analysis_text = response.candidates[0].content.parts[0].text
                    else:
                        raise ValueError("No text content in response")
                else:
                    raise ValueError("No content in response candidates")
            else:
                raise ValueError("No candidates in response")
        
        if not analysis_text or len(analysis_text.strip()) == 0:
            raise ValueError("Gemini API returned empty analysis text")
        
        # Only deduct credit and save after successful API call
        if current_user.role != "ADMIN":
            current_user.credits -= 1
            credits_used = 1
        
        # Save AI analysis to database
        db_analysis.ai_analysis = analysis_text
        db.commit()
        
    except HTTPException:
        # Re-raise HTTP exceptions (they already have proper error messages)
        raise
    except ValueError as e:
        # Handle value errors (empty response, etc.)
        import traceback
        print(f"Gemini API Value Error: {str(e)}")
        print(traceback.format_exc())
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI 분석 응답을 처리하는 중 오류가 발생했습니다. 티켓은 차감되지 않았습니다. 잠시 후 다시 시도해주세요."
        )
    except Exception as e:
        # Log the actual error for debugging
        import traceback
        print(f"Gemini API Error: {str(e)}")
        print(traceback.format_exc())
        
        # Rollback any partial changes (though we haven't deducted credits yet)
        db.rollback()
        
        # Handle API errors gracefully
        error_msg = str(e).lower()
        error_type = type(e).__name__
        
        # Check for specific Gemini API errors
        if "403" in str(e) or "permission denied" in error_msg or "leaked" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI 분석 서비스 인증에 실패했습니다. 관리자에게 문의해주세요."
            )
        elif "429" in str(e) or "rate limit" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI 분석 서비스가 일시적으로 혼잡합니다. 잠시 후 다시 시도해주세요."
            )
        elif "api key" in error_msg or "authentication" in error_msg or "unauthorized" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI 분석 서비스 인증에 실패했습니다. 관리자에게 문의해주세요."
            )
        else:
            # Return error message instead of generic fallback
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"AI 분석 중 오류가 발생했습니다. 티켓은 차감되지 않았습니다. 잠시 후 다시 시도해주세요."
            )
    
    # Get updated credits
    db.refresh(current_user)
    
    return AIAnalysisResponse(
        analysis=analysis_text,
        credits_used=credits_used,
        remaining_credits=current_user.credits
    )


# Credit charging endpoint
@app.post("/credits/charge", response_model=CreditChargeResponse)
async def charge_credits(
    request: CreditChargeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if request.amount <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="충전할 티켓 수는 1개 이상이어야 합니다."
        )
    
    current_user.credits += request.amount
    db.commit()
    db.refresh(current_user)

    # Record purchase history in database
    purchase = CreditPurchase(
        user_id=current_user.id,
        amount=request.amount,
        balance_after=current_user.credits,
        purchased_at=datetime.utcnow()
    )
    db.add(purchase)
    db.commit()
    
    return CreditChargeResponse(
        success=True,
        new_balance=current_user.credits,
        message=f"{request.amount}개의 분석 티켓이 충전되었습니다."
    )


# Analysis history endpoint
@app.get("/analysis/history")
async def get_analysis_history(
    current_user: User = Depends(get_current_user),
    limit: int = 10,
    db: Session = Depends(get_db)
):
    # Get recent analyses from database
    analyses = db.query(Analysis).filter(
        Analysis.user_id == current_user.id
    ).order_by(Analysis.uploaded_at.desc()).limit(limit).all()
    
    user_analyses = []
    for analysis in analyses:
        user_analyses.append({
            "scan_id": analysis.scan_id,
            "filename": analysis.filename,
            "risk_score": analysis.risk_score,
            "risk_level": analysis.risk_level,
            "uploaded_at": analysis.uploaded_at.isoformat() + "Z"
        })
    
    return {"analyses": user_analyses}


@app.delete("/analysis/{scan_id}")
async def delete_analysis(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete analysis result"""
    db_analysis = db.query(Analysis).filter(Analysis.scan_id == scan_id).first()
    if not db_analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="분석 결과를 찾을 수 없습니다."
        )
    
    # Check if user owns this analysis
    if db_analysis.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="이 분석 결과를 삭제할 권한이 없습니다."
        )
    
    # Delete from database
    db.delete(db_analysis)
    db.commit()
    
    return {"message": "분석 결과가 삭제되었습니다."}


@app.get("/analysis/{scan_id}", response_model=AnalysisDetailResponse)
async def get_analysis_detail(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get detailed analysis result for a specific scan_id from database.
    """
    db_analysis = db.query(Analysis).filter(Analysis.scan_id == scan_id).first()
    if not db_analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="분석 결과를 찾을 수 없습니다."
        )
    
    # Check if user owns this analysis
    if db_analysis.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="이 분석 결과에 접근할 권한이 없습니다."
        )

    analysis = db_analysis.analysis_data

    # Check if this is a URL analysis
    is_url_analysis = analysis.get("url") is not None or (
        db_analysis.filename and 
        (db_analysis.filename.startswith("http://") or db_analysis.filename.startswith("https://"))
    )

    if is_url_analysis:
        # URL analysis response
        url_analysis_result = analysis.get("url_analysis_result", {})
        return AnalysisDetailResponse(
            scan_id=scan_id,
            filename=db_analysis.filename,
            risk_score=analysis.get("risk_score", 0),
            risk_level=analysis.get("risk_level", "매우 낮음"),
            clamav_result=None,
            yara_matches=[],
            shellcode_patterns=[],
            suspicious_strings=[],
            spearphishing_indicators=None,
            external_apis=None,
            ai_analysis=None,  # URL analysis doesn't support AI analysis
            file_deleted_at="",  # Not applicable for URL analysis
            uploaded_at=db_analysis.uploaded_at.isoformat() + "Z",
            url=analysis.get("url") or db_analysis.filename,
            urlscan=analysis.get("urlscan_result") or url_analysis_result.get("urlscan"),
            ip_info=analysis.get("ip_info") or url_analysis_result.get("ip_info"),
            domain_info=analysis.get("domain_info") or url_analysis_result.get("domain_info", {}),
            analyzed_at=db_analysis.uploaded_at.isoformat() + "Z",
            url_analysis_result=url_analysis_result,
        )
    else:
        # File analysis response
        clamav_result = analysis.get("clamav_result")
        yara_matches = analysis.get("yara_matches", [])
        binary_analysis = analysis.get("binary_analysis", {})
        shellcode_patterns = binary_analysis.get("shellcode_patterns", [])
        suspicious_strings = binary_analysis.get("suspicious_strings", [])

        spearphishing_indicators = None
        if analysis.get("email_analysis"):
            email_analysis = analysis["email_analysis"]
            spearphishing_indicators = {
                "spoofed_sender": email_analysis.get("spoofed_sender", False),
                "phishing_keywords": email_analysis.get("phishing_keywords", []),
                "suspicious_urls": email_analysis.get("suspicious_urls", []),
                "has_double_extension": email_analysis.get("has_double_extension", False),
                "header_analysis": email_analysis.get("header_analysis", {}),
            }

        # File deletion time is approximated as upload time + 1 hour
        uploaded_at = db_analysis.uploaded_at
        file_deleted_at = (uploaded_at + timedelta(hours=1)).isoformat() + "Z"

        # Get external APIs data
        external_apis = analysis.get("external_apis", {})

        return AnalysisDetailResponse(
            scan_id=scan_id,
            filename=db_analysis.filename,
            risk_score=analysis["risk_score"],
            risk_level=analysis["risk_level"],
            clamav_result=clamav_result,
            yara_matches=yara_matches,
            shellcode_patterns=shellcode_patterns,
            suspicious_strings=suspicious_strings,
            spearphishing_indicators=spearphishing_indicators,
            external_apis=external_apis,
            ai_analysis=db_analysis.ai_analysis,
            file_deleted_at=file_deleted_at,
            uploaded_at=uploaded_at.isoformat() + "Z",
            # Enhanced analysis fields
            entropy=analysis.get("entropy"),
            file_type_analysis=analysis.get("file_type_analysis"),
            office_analysis=analysis.get("office_analysis"),
            pdf_analysis=analysis.get("pdf_analysis"),
            zip_analysis=analysis.get("zip_analysis"),
            pe_enhanced=analysis.get("pe_enhanced"),
            strings_enhanced=analysis.get("strings_enhanced"),
            file_hashes=analysis.get("file_hashes"),
            file_size_analysis=analysis.get("file_size_analysis"),
            filename_pattern_analysis=analysis.get("filename_pattern_analysis"),
            base64_analysis=analysis.get("base64_analysis"),
        )


@app.get("/credits/history", response_model=List[CreditPurchaseHistoryItem])
async def get_credit_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get credit purchase history for the current user from database.
    """
    purchases = db.query(CreditPurchase).filter(
        CreditPurchase.user_id == current_user.id
    ).order_by(CreditPurchase.purchased_at.asc()).all()
    
    # Return in chronological order (oldest first)
    return [
        CreditPurchaseHistoryItem(
            purchased_at=purchase.purchased_at.isoformat() + "Z",
            amount=purchase.amount,
            balance_after=purchase.balance_after,
        )
        for purchase in purchases
    ]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

