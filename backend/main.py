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
    file_deleted_at: str


class AIAnalysisRequest(BaseModel):
    scan_id: str


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
    filename: str
    risk_score: int
    risk_level: str
    clamav_result: Optional[str]
    yara_matches: List[str]
    shellcode_patterns: List[str]
    suspicious_strings: List[str]
    spearphishing_indicators: Optional[Dict]
    ai_analysis: Optional[str] = None
    file_deleted_at: str
    uploaded_at: str


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
    
    # Prepare Gemini prompt (Korean, no emojis)
    prompt = f"""당신은 20년 경력의 사이버 보안 전문가입니다. 일반인도 이해할 수 있게 쉽게 설명해주세요.

**분석 결과:**

- 파일명: {filename}
- 위험도 점수: {analysis_data['risk_score']}/100
- 위험도 등급: {analysis_data['risk_level']}
- ClamAV 탐지: {analysis_data.get('clamav_result', '없음')}
- YARA 탐지 규칙: {', '.join(analysis_data.get('yara_matches', [])) if analysis_data.get('yara_matches') else '없음'}
- 쉘코드 패턴: {', '.join(analysis_data.get('binary_analysis', {}).get('shellcode_patterns', [])) if analysis_data.get('binary_analysis', {}).get('shellcode_patterns') else '없음'}
- 의심스러운 문자열: {', '.join(analysis_data.get('binary_analysis', {}).get('suspicious_strings', [])[:10]) if analysis_data.get('binary_analysis', {}).get('suspicious_strings') else '없음'}
- 스피어피싱 지표: {json.dumps(analysis_data.get('email_analysis', {}), ensure_ascii=False, indent=2) if analysis_data.get('email_analysis') else '없음'}

**작업:**

위 분석 결과를 바탕으로 다음 형식으로 상세하고 구체적인 분석을 제공해주세요. 이모티콘은 사용하지 마세요.

## 위험도 평가

{analysis_data['risk_level']} - 위험도 점수 {analysis_data['risk_score']}/100에 대한 상세 평가

## 3줄 요약

1. 이 파일의 정체가 무엇인지 (구체적으로)
2. 어떤 위험이 있는지 (실제로 발생할 수 있는 피해)
3. 왜 위험한지 (기술적 근거)

## 스피어피싱 가능성

이 파일이 스피어피싱 공격의 일부일 확률을 0-100%로 평가하고 근거를 제시해주세요.

## 발견된 위협 요소

- ClamAV 탐지 결과에 대한 분석
- YARA 규칙 매칭의 의미
- 쉘코드 패턴이 발견되었다면 그 의미
- 의심스러운 문자열의 위험성
- 스피어피싱 지표가 있다면 상세 분석

## 대응 방법

1. 즉시 해야 할 조치 (구체적인 단계)
2. 예방을 위한 조치 (장기적 대응)

## 유사 공격 사례

실제 발생했던 유사한 공격 사례 1개를 간단히 소개해주세요.

**중요:**
- 전문 용어 사용 시 괄호로 쉬운 설명 추가 (예: "쉘코드(악성 명령어)")
- 위험도를 과장하거나 축소하지 말 것
- 구체적인 증거 기반으로만 설명
- 모든 설명은 한국어로 작성
- 이모티콘 사용 금지
- 일반적인 설명이 아닌 이 파일에 특화된 구체적인 분석 제공
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
                'max_output_tokens': 2000,
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

    # Reuse the same structure as file upload response
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
        ai_analysis=db_analysis.ai_analysis,
        file_deleted_at=file_deleted_at,
        uploaded_at=uploaded_at.isoformat() + "Z",
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

