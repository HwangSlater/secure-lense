# SecureLens - AI 기반 악성코드 및 스피어피싱 분석 플랫폼

SecureLens는 보안 전문가가 수동으로 수행하던 악성코드 분석 작업을 자동화하고, Gemini AI를 활용하여 분석 결과를 쉽게 이해할 수 있도록 설명해주는 웹 기반 분석 서비스입니다.

## 🚀 빠른 시작

### 필수 요구사항

- Docker 및 Docker Compose
- Google Gemini API 키 ([여기서 발급받기](https://makersuite.google.com/app/apikey))

### 설치 방법

1. **저장소 클론**

```bash
git clone <repository-url>
cd secure
```

2. **환경 변수 설정**

프로젝트 루트에 `.env` 파일을 생성하세요:

```env
# Gemini API
GEMINI_API_KEY=your_gemini_api_key_here

# Database
DATABASE_URL=sqlite:///./securelens.db

# Security
JWT_SECRET=your_secret_key_here_change_in_production
UPLOAD_MAX_SIZE=52428800

# Rate Limiting
MAX_UPLOADS_PER_HOUR=10
```

3. **서비스 시작**

```bash
docker-compose up --build
```

4. **애플리케이션 접속**

- 프론트엔드: http://localhost:3000
- 백엔드 API: http://localhost:8000
- API 문서: http://localhost:8000/docs

## 🔐 테스트 계정

| 역할   | 사용자명 | 비밀번호 | 크레딧 |
|--------|----------|----------|---------|
| 관리자 | admin    | admin123 | ∞       |
| 사용자 | user     | user123  | 0       |

## 📋 주요 기능

### 핵심 기능

- ✅ **다중 엔진 악성코드 스캔**
  - ClamAV 바이러스 시그니처 탐지
  - YARA 패턴 매칭 규칙
  - 심층 바이너리 분석 (HxD와 유사한 자동화)
  - PE 헤더 이상 탐지

- ✅ **스피어피싱 탐지**
  - 이메일 헤더 분석 (From, Reply-To, Return-Path)
  - 발신자 위조 탐지
  - 한국어 피싱 키워드 탐지
  - 호모그래프 공격 탐지
  - 의심스러운 URL 추출
  - 이중 확장자 탐지

- ✅ **AI 기반 위협 설명**
  - Gemini 1.5 Flash 통합
  - 한국어 설명
  - 위험도 평가 및 권장사항
  - 실제 공격 사례 참조

- ✅ **크레딧 기반 AI 분석**
  - AI 분석 접근을 위한 크레딧 시스템
  - 관리자는 무제한 접근
  - 모의 결제 시스템

- ✅ **보안 기능**
  - 자동 파일 정리 (1시간 후 삭제)
  - 속도 제한 (IP당 시간당 10개 업로드)
  - 파일 격리 저장 (`/tmp/securelens_uploads/`)
  - 타임아웃 보호 (모든 스캔에 30초 제한)
  - 입력 검증 및 정제

### 지원 파일 형식

- **실행 파일**: `.exe`, `.dll`
- **문서**: `.pdf`, `.docx`
- **이메일**: `.eml`
- **압축 파일**: `.zip`

### 파일 크기 제한

- 최대: **50MB**

## 🎯 위험도 점수 계산

위험도 점수 (0-100)는 다음과 같이 계산됩니다:

- **ClamAV 탐지**: +40점
- **YARA 매칭**: +30점 (최대 30점)
- **쉘코드 패턴**: +20점
- **의심스러운 문자열**: +10점 (5개 이상 발견 시)
- **스피어피싱 지표**: +20점
  - 발신자 위조: +10점
  - 피싱 키워드: +20점 (키워드당 5점)
  - 이중 확장자: +10점
  - 다수의 의심스러운 URL: +10점

**위험도 등급**:
- 🟢 **매우 낮음** (0-20)
- 🟡 **낮음** (21-40)
- 🟠 **보통** (41-60)
- 🔴 **높음** (61-80)
- ⚫ **매우 높음** (81-100)

## 🧪 테스트

### 테스트 실행

```bash
cd tests
pytest test_analyzer.py -v
```

### 테스트 파일

테스트 파일은 `tests/sample_files/` 디렉토리에 있습니다:

- `eicar.com` - 표준 EICAR 테스트 파일 (ClamAV가 탐지해야 함)
- `clean_file.txt` - 무해한 텍스트 파일
- `phishing_email.eml` - 샘플 한국어 스피어피싱 이메일
- `invoice.pdf.exe` - 이중 확장자를 가진 파일

### 테스트 케이스

- `test_eicar_detection()` - ClamAV 탐지 테스트
- `test_clean_file()` - 깨끗한 파일 검증
- `test_spearphishing_email()` - 이메일 피싱 탐지
- `test_double_extension()` - 이중 확장자 탐지
- `test_file_validation_extension()` - 파일 확장자 검증

## 🛡️ 보안 기능

### 파일 안전성

- **파일 실행 금지** - 정적 분석만 수행
- **격리 저장** - 파일은 `/tmp/securelens_uploads/`에 저장
- **자동 삭제** - 파일은 1시간 후 자동 삭제
- **크기 제한** - 최대 50MB 파일 크기
- **확장자 화이트리스트** - 허용된 파일 형식만

### API 보안

- **JWT 인증** - 토큰 기반 인증
- **속도 제한** - IP당 시간당 10개 업로드
- **입력 검증** - 모든 입력 검증 및 정제
- **타임아웃 보호** - 모든 스캔에 30초 타임아웃
- **오류 처리** - 사용자 친화적인 메시지로 우아한 오류 처리

## 📁 프로젝트 구조

```
SecureLens/
├── backend/
│   ├── main.py                 # FastAPI 애플리케이션, 라우트
│   ├── models.py               # SQLAlchemy 사용자 모델
│   ├── auth.py                 # JWT 인증
│   ├── analyzer.py             # 핵심 분석 로직
│   ├── rules/
│   │   ├── malware_general.yar
│   │   └── spearphishing.yar
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── app/
│   │   ├── page.tsx            # 메인 대시보드
│   │   ├── login/
│   │   │   └── page.tsx
│   │   ├── dashboard/
│   │   │   └── page.tsx
│   │   └── layout.tsx
│   ├── components/
│   │   ├── FileUpload.tsx
│   │   ├── AnalysisResult.tsx
│   │   ├── AIInsight.tsx
│   │   └── CreditCharge.tsx
│   ├── package.json
│   └── Dockerfile
├── tests/
│   ├── sample_files/
│   │   ├── eicar.com
│   │   ├── clean_file.txt
│   │   ├── phishing_email.eml
│   │   └── invoice.pdf.exe
│   └── test_analyzer.py
├── docker-compose.yml
└── README.md
```

## 🔧 설정

### 환경 변수

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `GEMINI_API_KEY` | Google Gemini API 키 | 필수 |
| `DATABASE_URL` | SQLite 데이터베이스 URL | `sqlite:///./securelens.db` |
| `JWT_SECRET` | JWT 서명 시크릿 | `your-secret-key-change-in-production` |
| `UPLOAD_MAX_SIZE` | 최대 파일 크기 (바이트) | `52428800` (50MB) |
| `MAX_UPLOADS_PER_HOUR` | IP당 속도 제한 | `10` |
| `UPLOAD_DIR` | 파일 업로드 디렉토리 | `/tmp/securelens_uploads` |

### YARA 규칙

커스텀 YARA 규칙은 `backend/rules/` 디렉토리에 추가할 수 있습니다:

- `malware_general.yar` - 일반 악성코드 탐지 규칙
- `spearphishing.yar` - 스피어피싱 특화 규칙

## 🌐 API 엔드포인트

### 인증

- `POST /auth/login` - 사용자 로그인
- `GET /auth/me` - 현재 사용자 정보 가져오기

### 파일 분석

- `POST /files/upload` - 파일 업로드 및 분석
- `POST /analysis/ai` - AI 기반 분석 가져오기
- `GET /analysis/history` - 분석 이력 가져오기

### 크레딧

- `POST /credits/charge` - 분석 크레딧 충전

## 🎨 UI/UX 기능

- **한국어 인터페이스** - 모든 UI 텍스트가 한국어
- **반응형 디자인** - 모바일 친화적 레이아웃
- **실시간 진행 상황** - 업로드 진행률 표시기
- **색상 코딩된 위험도** - 시각적 위험도 평가
- **2열 레이아웃** - 기술 분석 + AI 인사이트
- **잠긴 AI 분석** - 크레딧 기반 접근 제어

## ⚠️ 중요 사항

1. **업로드된 파일 실행 금지** - 이것은 정적 분석 도구일 뿐입니다
2. **프로덕션 배포** - 기본 JWT 시크릿을 변경하고 적절한 시크릿 관리 사용
3. **ClamAV 연결** - ClamAV 서비스가 실행 중이고 접근 가능한지 확인
4. **Gemini API** - AI 분석 기능을 사용하려면 유효한 API 키 필요
5. **파일 정리** - 파일은 1시간 후 자동으로 삭제됩니다

## 🐛 문제 해결

### ClamAV 연결 문제

ClamAV 스캔이 실패하는 경우 다음을 확인하세요:
- ClamAV 서비스 실행 중: `docker ps | grep clamav`
- 백엔드와 ClamAV 간 네트워크 연결
- ClamAV가 포트 3310에서 수신 대기 중인지 확인

### Gemini API 오류

- `.env` 파일에 API 키가 올바르게 설정되었는지 확인
- API 키에 적절한 권한이 있는지 확인
- API 할당량 제한 확인

### 파일 업로드 문제

- 파일 크기가 50MB 미만인지 확인
- 파일 확장자가 화이트리스트에 있는지 확인
- 업로드 디렉토리가 존재하고 쓰기 가능한지 확인

## 📚 추가 자료

- [FastAPI 문서](https://fastapi.tiangolo.com/)
- [Next.js 문서](https://nextjs.org/docs)
- [YARA 문서](https://yara.readthedocs.io/)
- [ClamAV 문서](https://docs.clamav.net/)
- [Gemini API 문서](https://ai.google.dev/docs)

## 📄 라이선스

이 프로젝트는 교육 및 보안 연구 목적으로만 사용됩니다.

## 🤝 기여하기

기여를 환영합니다! 다음 사항을 준수해주세요:
- 코드는 기존 스타일 규칙을 따릅니다
- 모든 테스트가 통과합니다
- 새 기능에는 적절한 테스트가 포함됩니다
- UI 텍스트는 한국어로 유지됩니다
- 소스 코드는 영어로 유지됩니다

## 📧 지원

문제나 질문이 있으시면 저장소에 이슈를 등록해주세요.

---

**보안 전문가를 위해 ❤️로 만들어졌습니다**
