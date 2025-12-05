'use client'

import React, { useState } from 'react'

interface AnalysisResultProps {
  data: {
    scan_id: string
    filename: string
    risk_score: number
    risk_level: string
    clamav_result: string | null
    yara_matches: string[]
    shellcode_patterns: string[]
    suspicious_strings: string[]
    spearphishing_indicators: any
    entropy?: number
    file_type_analysis?: {
      actual_type?: string
      extension_match?: boolean
      suspicious?: boolean
    }
    office_analysis?: {
      has_macros?: boolean
      macro_count?: number
      auto_exec_macros?: boolean
      suspicious_macros?: string[]
    }
    pdf_analysis?: {
      has_javascript?: boolean
      has_forms?: boolean
      has_actions?: boolean
      page_count?: number
      suspicious_objects?: string[]
    }
    zip_analysis?: {
      file_count?: number
      suspicious_files?: string[]
      encrypted?: boolean
      nested_archives?: boolean
      double_extension_files?: string[]
    }
    pe_enhanced?: {
      suspicious_characteristics?: string[]
      sections?: Array<{
        name: string
        entropy: number
        characteristics: string[]
      }>
    }
    strings_enhanced?: {
      urls?: string[]
      ips?: string[]
      email_addresses?: string[]
    }
    file_hashes?: {
      md5?: string
      sha1?: string
      sha256?: string
    }
    file_size_analysis?: {
      size_bytes?: number
      size_mb?: number
      suspicious?: boolean
      anomalies?: string[]
    }
    filename_pattern_analysis?: {
      suspicious?: boolean
      anomalies?: string[]
      patterns_detected?: string[]
    }
    base64_analysis?: {
      has_base64?: boolean
      suspicious?: boolean
      anomalies?: string[]
      base64_strings?: Array<{
        string: string
        decoded_size: number
        offset: string
      }>
    }
    external_apis?: {
      file_hashes?: {
        md5?: string
        sha1?: string
        sha256?: string
      }
      virustotal?: {
        detected: number
        total: number
        scan_date?: string
        permalink?: string
      }
      malwarebazaar?: {
        sha256_hash?: string
        file_name?: string
        file_type?: string
        signature?: string
        tags?: string[]
        first_seen?: string
      }
      url_scans?: Array<{
        url: string
        domain: string
        malicious: boolean
        threat_score: number
        tags: string[]
      }>
      ip_info?: Array<{
        ip: string
        country: string
        city: string
        isp: string
      }>
    }
  }
}

const getRiskColor = (riskLevel: string) => {
  switch (riskLevel) {
    case '매우 낮음':
      return 'text-green-400 bg-green-900/30 border border-green-700/50'
    case '낮음':
      return 'text-yellow-400 bg-yellow-900/30 border border-yellow-700/50'
    case '보통':
      return 'text-orange-400 bg-orange-900/30 border border-orange-700/50'
    case '높음':
      return 'text-red-400 bg-red-900/30 border border-red-700/50'
    case '매우 높음':
      return 'text-red-300 bg-red-900/40 border border-red-600/50'
    default:
      return 'text-slate-400 bg-slate-800/30 border border-slate-700/50'
  }
}

const getRiskGaugeColor = (score: number) => {
  if (score <= 20) return 'bg-green-500'
  if (score <= 40) return 'bg-yellow-500'
  if (score <= 60) return 'bg-orange-500'
  if (score <= 80) return 'bg-red-500'
  return 'bg-red-700'
}

const getRiskDescription = (riskLevel: string) => {
  switch (riskLevel) {
    case '매우 낮음':
      return '현재로서는 악성일 가능성이 매우 낮은 상태입니다. 추가 행동 없이 모니터링만 해도 충분합니다.'
    case '낮음':
      return '악성 가능성이 낮지만, 중요한 업무 환경이라면 열람 전에 한 번 더 확인하는 것을 권장합니다.'
    case '보통':
      return '악성 징후가 일부 발견되었습니다. 발신자/출처를 다시 확인하고, 신뢰할 수 없는 경우 실행을 피하는 것이 좋습니다.'
    case '높음':
      return '여러 악성 패턴이 감지되었습니다. 해당 파일을 실행하거나 열지 말고, 격리 또는 삭제하는 것을 권장합니다.'
    case '매우 높음':
      return '악성코드일 가능성이 매우 높습니다. 즉시 격리 또는 삭제하고, 관련 메일/파일 공유를 중단하는 것이 좋습니다.'
    default:
      return '분석 결과를 기반으로 위험도를 산정했습니다. 세부 항목을 참고하여 실제 업무 환경에 맞게 판단해 주세요.'
  }
}

const getUserFriendlySummary = (data: AnalysisResultProps['data']) => {
  const messages: string[] = []

  if (data.clamav_result) {
    messages.push('백신 엔진(ClamAV)이 악성 시그니처를 직접 탐지했습니다. 실제 악성코드일 가능성이 큽니다.')
  } else {
    messages.push('백신 엔진(ClamAV)에서는 알려진 악성 시그니처를 찾지 못했습니다.')
  }

  if (data.yara_matches.length > 0) {
    messages.push('전문가용 YARA 규칙에서 의심스러운 패턴을 감지했습니다. 악성코드에 사용되는 전형적인 코드 조각일 수 있습니다.')
  } else {
    messages.push('YARA 규칙에서도 특이한 악성 패턴은 감지되지 않았습니다.')
  }

  if (data.shellcode_patterns.length > 0) {
    messages.push('프로세스 제어를 시도하는 쉘코드 패턴이 포함되어 있습니다. 취약점을 악용해 시스템을 장악하려는 시도로 보일 수 있습니다.')
  }

  if (data.suspicious_strings.length > 0) {
    messages.push('외부 접속 주소나 명령어 등, 공격에 자주 쓰이는 문자열이 포함되어 있습니다. 통신 시도나 추가 다운로드 가능성을 의심해야 합니다.')
  }

  if (data.spearphishing_indicators) {
    const s = data.spearphishing_indicators
    if (s.spoofed_sender) {
      messages.push('이메일 발신자 정보가 실제 주소와 다르게 보이도록 위조된 흔적이 있습니다. 발신자를 신뢰하기 어렵습니다.')
    }
    if (s.phishing_keywords && s.phishing_keywords.length > 0) {
      messages.push('긴급 안내, 계좌 확인 등 피싱에 자주 쓰이는 단어들이 이메일 본문에서 발견되었습니다. 금전/계정 정보 요구에 특히 주의하세요.')
    }
    if (s.suspicious_urls && s.suspicious_urls.length > 0) {
      messages.push('클릭 시 위험 사이트로 연결될 수 있는 의심스러운 링크가 포함되어 있습니다. 주소를 직접 확인하기 전까지는 클릭하지 마세요.')
    }
    if (s.has_double_extension) {
      messages.push('파일명이 이중 확장자 형태(예: invoice.pdf.exe)로 되어 있어, 사용자를 속이기 위한 의도일 수 있습니다.')
    }
  }

  return messages
}

const SectionIcon = ({ type }: { type: 'score' | 'engine' | 'email' | 'timeline' }) => {
  const base = 'h-5 w-5 mr-2 text-cyan-400'
  switch (type) {
    case 'score':
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" />
          <path d="M12 7v5l3 3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )
    case 'engine':
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none">
          <rect x="4" y="5" width="16" height="14" rx="2" stroke="currentColor" strokeWidth="1.6" />
          <path d="M4 10h16" stroke="currentColor" strokeWidth="1.6" />
          <circle cx="8" cy="8" r="0.8" fill="currentColor" />
          <circle cx="11" cy="8" r="0.8" fill="currentColor" />
          <circle cx="14" cy="8" r="0.8" fill="currentColor" />
        </svg>
      )
    case 'email':
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none">
          <rect x="4" y="5" width="16" height="14" rx="2" stroke="currentColor" strokeWidth="1.6" />
          <path d="M5 7l7 5 7-5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )
    case 'timeline':
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none">
          <path d="M7 6h10M7 12h5M7 18h8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          <circle cx="5" cy="6" r="1" fill="currentColor" />
          <circle cx="5" cy="12" r="1" fill="currentColor" />
          <circle cx="5" cy="18" r="1" fill="currentColor" />
        </svg>
      )
  }
}

// 툴 간단 설명 데이터 (행 클릭 시 표시)
const toolDescriptions: Record<string, string> = {
  'ClamAV': '바이러스 시그니처 기반 탐지 엔진입니다. 알려진 악성코드의 고유 패턴(시그니처)을 데이터베이스와 비교하여 탐지합니다.',
  'YARA 규칙': '패턴 매칭 규칙 엔진입니다. YARA 규칙을 사용하여 악성코드의 특징적인 패턴을 탐지합니다.',
  '엔트로피 분석': '파일의 무작위성을 측정하여 패킹(압축) 또는 암호화 여부를 판단합니다. 0-8.0 척도로 측정합니다.',
  '파일 타입 검증': '실제 파일 시그니처(매직 넘버)를 확인하여 확장자 위조를 탐지합니다.',
  '파일 해시': '파일의 고유 식별자(MD5, SHA1, SHA256)를 계산합니다. 외부 위협 인텔리전스 서비스와 연동에 사용됩니다.',
  '파일 크기 분석': '비정상적으로 작거나 큰 파일을 탐지합니다.',
  '파일명 패턴 분석': '의심스러운 파일명 패턴을 탐지합니다. 이중 확장자, 피싱 키워드, 랜덤 파일명 등을 탐지합니다.',
  'Base64 인코딩 탐지': '파일 내 Base64로 인코딩된 데이터를 탐지합니다.',
  'PE 강화 분석': 'LIEF 라이브러리를 사용한 상세 PE 파일 분석입니다. 섹션 엔트로피, API 임포트 등을 분석합니다.',
  '쉘코드 탐지': '프로세스 제어를 시도하는 코드 패턴을 탐지합니다.',
  '의심 문자열 분석': '파일 내 의심스러운 문자열을 추출합니다. 악성 행위와 관련된 키워드를 탐지합니다.',
  'Office 문서 분석': 'Office 문서의 VBA 매크로를 분석합니다. 매크로 존재 여부 및 자동 실행 매크로를 탐지합니다.',
  'PDF 분석': 'PDF 파일의 의심스러운 요소를 탐지합니다. JavaScript 포함 여부 및 인터랙티브 요소를 확인합니다.',
  'ZIP 분석': '압축 파일 내부의 위험 요소를 탐지합니다. 이중 확장자, 실행 파일, 암호화 등을 확인합니다.',
  '스피어피싱 지표': '이메일 기반 공격(스피어피싱)의 징후를 탐지합니다.',
  'VirusTotal': '다수의 백신 엔진을 사용하는 위협 인텔리전스 서비스입니다.',
  'MalwareBazaar': 'Abuse.ch에서 운영하는 악성코드 샘플 데이터베이스입니다.',
  'URL 스캔': '파일 내부에서 추출된 URL을 VirusTotal과 URLScan.io를 통해 분석합니다. VirusTotal은 다수의 백신 엔진으로 악성 URL을 탐지하고, URLScan.io는 URL의 동작, 스크린샷, 네트워크 요청 등을 기록합니다.',
  'IP 정보 조회': '파일 내부에서 추출된 IP 주소의 지오로케이션 정보를 조회합니다.',
}

// 툴 상세 설명 데이터 (이름 클릭 시 표시 - 기능 + 탐지 시 의미)
const toolDetailedDescriptions: Record<string, string> = {
  'ClamAV': '바이러스 시그니처 기반 탐지 엔진입니다. 알려진 악성코드의 고유 패턴(시그니처)을 데이터베이스와 비교하여 탐지합니다. 트로이 목마, 웜, 랜섬웨어 등 다양한 악성코드를 탐지할 수 있습니다.\n\n탐지가 되었을 경우: 해당 파일이 알려진 악성코드로 판단됩니다. 즉시 실행을 중단하고 격리하거나 삭제해야 합니다. 위험도 점수에 +40점이 추가됩니다.',
  'YARA 규칙': '패턴 매칭 규칙 엔진입니다. YARA 규칙을 사용하여 악성코드의 특징적인 패턴을 탐지합니다. 쉘코드 패턴, 자격 증명 탈취 행위, 한국어 피싱 키워드, 이중 확장자 파일 등을 탐지할 수 있습니다.\n\n탐지가 되었을 경우: 파일이 악성코드의 특징적인 패턴을 가지고 있음을 의미합니다. 해당 패턴의 종류와 개수에 따라 위험도가 달라지며, 최대 +30점이 추가됩니다.',
  '엔트로피 분석': '파일의 무작위성을 측정하여 패킹(압축) 또는 암호화 여부를 판단합니다. 0-8.0 척도로 측정하며, 7.0 이상이면 패킹/암호화 가능성이 높습니다. 악성코드는 분석을 피하기 위해 패킹을 자주 사용합니다.\n\n높은 엔트로피가 탐지되었을 경우: 파일이 패킹되거나 암호화되었을 가능성이 높습니다. 이는 악성코드가 분석을 회피하기 위해 사용하는 기법입니다. 엔트로피가 7.5 이상이면 +20점, 7.0-7.5면 +15점이 추가됩니다.',
  '파일 타입 검증': '실제 파일 시그니처(매직 넘버)를 확인하여 확장자 위조를 탐지합니다. 예를 들어 실제 실행 파일인데 .pdf 확장자를 가진 경우를 탐지합니다. 피싱 공격에서 자주 사용되는 기법입니다.\n\n확장자 위조가 탐지되었을 경우: 파일의 실제 타입과 확장자가 일치하지 않습니다. 이는 사용자를 속이기 위한 시도로, 실제 실행 파일을 문서 파일로 위장한 경우가 많습니다. +15점이 추가됩니다.',
  '파일 해시': '파일의 고유 식별자(MD5, SHA1, SHA256)를 계산합니다. 동일 파일 여부 확인, VirusTotal 및 MalwareBazaar와 같은 외부 위협 인텔리전스 서비스와 연동하여 알려진 악성코드를 검색하는 데 사용됩니다.\n\n해시 계산 자체는 위험도를 직접적으로 증가시키지 않지만, 계산된 해시를 통해 외부 서비스에서 알려진 악성코드인지 확인할 수 있습니다.',
  '파일 크기 분석': '비정상적으로 작거나 큰 파일을 탐지합니다. 1KB 미만의 파일은 드로퍼(추가 데이터를 다운로드하는 악성코드) 가능성이 있고, 100MB 초과는 데이터 유출 시도 가능성이 있습니다.\n\n이상 크기가 탐지되었을 경우: 파일 크기가 비정상적입니다. 매우 작은 파일은 추가 악성 페이로드를 다운로드하는 드로퍼일 수 있고, 매우 큰 파일은 데이터 유출 시도일 수 있습니다. +10점이 추가됩니다.',
  '파일명 패턴 분석': '의심스러운 파일명 패턴을 탐지합니다. 이중 확장자(예: invoice.pdf.exe), 피싱 키워드(긴급, 확인 등), 랜덤 파일명, 호모그래프 공격(유니코드 문자 사용) 등을 탐지합니다.\n\n의심스러운 패턴이 탐지되었을 경우: 파일명이 피싱 공격이나 악성코드의 특징을 보입니다. 이중 확장자는 사용자를 속이기 위한 시도이고, 피싱 키워드는 긴급성을 조성하려는 시도입니다. +15점이 추가됩니다.',
  'Base64 인코딩 탐지': '파일 내 Base64로 인코딩된 데이터를 탐지합니다. 악성코드가 페이로드를 숨기거나 난독화하기 위해 Base64 인코딩을 사용하는 경우가 많습니다. 다수의 Base64 문자열이나 대용량 데이터는 의심스러울 수 있습니다.\n\n의심스러운 Base64 인코딩이 탐지되었을 경우: 파일 내부에 난독화된 페이로드가 숨겨져 있을 가능성이 높습니다. 악성코드는 분석을 피하기 위해 Base64로 인코딩하여 숨기는 경우가 많습니다. +15점이 추가됩니다.',
  'PE 강화 분석': 'LIEF 라이브러리를 사용한 상세 PE 파일 분석입니다. 각 섹션의 엔트로피, 임포트/익스포트 함수, 섹션 특성(실행 가능 + 쓰기 가능 등)을 분석하여 악성 행위를 탐지합니다.\n\n의심스러운 특성이 탐지되었을 경우: PE 파일의 구조가 비정상적입니다. 고엔트로피 섹션은 패킹을 의미하고, 실행 가능 + 쓰기 가능한 섹션은 코드 주입 가능성을 의미합니다. +20점이 추가됩니다.',
  '쉘코드 탐지': '프로세스 제어를 시도하는 코드 패턴을 탐지합니다. NOP sled, JMP/CALL/PUSH 명령어 시퀀스 등 쉘코드의 특징적인 패턴을 찾아냅니다. 쉘코드는 악성코드가 시스템을 제어하기 위해 사용하는 코드입니다.\n\n쉘코드가 탐지되었을 경우: 파일 내부에 시스템을 제어하려는 악성 코드가 포함되어 있습니다. 이는 매우 위험한 신호로, 즉시 실행을 중단해야 합니다. +20점이 추가됩니다.',
  '의심 문자열 분석': '파일 내 의심스러운 문자열을 추출합니다. cmd.exe, powershell, 레지스트리 조작, 네트워크 API, 메모리 조작 등의 의심스러운 키워드를 탐지합니다.\n\n의심스러운 문자열이 탐지되었을 경우: 파일이 시스템을 조작하거나 네트워크 통신을 시도하는 코드를 포함하고 있습니다. 5개 이상이면 +15점, 3개 이상이면 +10점이 추가됩니다.',
  'Office 문서 분석': 'Office 문서의 VBA 매크로를 분석합니다. 매크로 존재 여부, 자동 실행 매크로(Auto_Open 등), 의심스러운 VBA 키워드(Shell, CreateObject 등)를 탐지합니다. 악성 Office 문서는 매크로를 통해 악성 코드를 실행합니다.\n\n매크로가 탐지되었을 경우: Office 문서에 VBA 매크로가 포함되어 있습니다. 특히 자동 실행 매크로는 문서를 열면 자동으로 실행되므로 매우 위험합니다. 자동 실행 매크로는 +20점, 일반 매크로는 +15점이 추가됩니다.',
  'PDF 분석': 'PDF 파일의 의심스러운 요소를 탐지합니다. JavaScript 포함 여부, 인터랙티브 요소(액션, 폼), 임베디드 파일 등을 확인합니다. 악성 PDF는 JavaScript를 통해 악성 코드를 실행할 수 있습니다.\n\nJavaScript가 탐지되었을 경우: PDF 파일에 JavaScript 코드가 포함되어 있습니다. 악성 PDF는 JavaScript를 통해 시스템 명령을 실행하거나 추가 악성 파일을 다운로드할 수 있습니다. +15점이 추가됩니다.',
  'ZIP 분석': '압축 파일 내부의 위험 요소를 탐지합니다. 이중 확장자 파일, 실행 파일, 중첩 아카이브, 암호화된 파일 등을 확인합니다. 피싱 공격에서 악성 파일을 압축하여 전송하는 경우가 많습니다.\n\n의심스러운 파일이 탐지되었을 경우: ZIP 파일 내부에 위험한 파일이 포함되어 있습니다. 이중 확장자 파일이나 실행 파일은 사용자를 속이기 위한 시도입니다. +15점이 추가됩니다.',
  '스피어피싱 지표': '이메일 기반 공격(스피어피싱)의 징후를 탐지합니다. 발신자 위조, 피싱 키워드, 의심스러운 URL, 이중 확장자 첨부파일 등을 확인합니다.\n\n스피어피싱 지표가 탐지되었을 경우: 이메일이 피싱 공격의 일부일 가능성이 높습니다. 발신자 위조, 피싱 키워드, 의심스러운 URL 등이 발견되면 해당 이메일을 신뢰하지 말고 첨부파일을 실행하지 않아야 합니다. +10~20점이 추가됩니다.',
  'VirusTotal': '다수의 백신 엔진을 사용하는 위협 인텔리전스 서비스입니다. 파일 해시를 기반으로 다수의 백신 엔진이 해당 파일을 어떻게 판단했는지 확인할 수 있습니다.\n\n탐지가 되었을 경우: 다수의 백신 엔진이 해당 파일을 악성으로 판단했습니다. 탐지 비율이 50% 이상이면 +35점, 20-50%면 +25점, 그 이하는 +15점이 추가됩니다. 이는 매우 신뢰할 수 있는 신호입니다.',
  'MalwareBazaar': 'Abuse.ch에서 운영하는 악성코드 샘플 데이터베이스입니다. 파일 해시를 기반으로 알려진 악성코드 샘플인지 확인할 수 있습니다.\n\n매칭이 되었을 경우: 해당 파일이 알려진 악성코드 샘플입니다. 이미 악성코드로 확인된 파일이므로 즉시 삭제해야 합니다. +20점이 추가됩니다.',
  'URL 스캔': '파일 내부에서 추출된 URL을 VirusTotal과 URLScan.io를 통해 분석합니다. VirusTotal은 다수의 백신 엔진을 사용하여 악성 URL을 탐지하는 데 더 정확합니다. URLScan.io는 URL의 동작을 분석하고 스크린샷, 네트워크 요청, 페이지 구조 등을 기록하여 제공합니다.\n\nVirusTotal이 악성으로 탐지했을 경우: 파일 내부에 포함된 URL이 다수의 백신 엔진에 의해 악성으로 판단되었습니다. 이는 피싱 사이트나 C2(Command & Control) 서버일 가능성이 매우 높습니다. 해당 URL로 접속하지 않아야 합니다. 탐지 비율에 따라 +15~30점이 추가됩니다.\n\nURLScan.io가 악성으로 판단했을 경우: URL의 동작 분석 결과 악성으로 판단되었습니다. 위협 점수가 높거나 의심스러운 동작이 발견된 경우, 해당 URL로 접속하지 않아야 합니다. +15점이 추가됩니다.',
  'IP 정보 조회': '파일 내부에서 추출된 IP 주소의 지오로케이션 정보를 조회합니다. IP 주소의 국가, 도시, ISP 정보를 확인하여 의심스러운 위치의 IP를 탐지할 수 있습니다.\n\n의심스러운 IP가 발견되었을 경우: 파일 내부에 포함된 IP 주소가 의심스러운 위치에 있습니다. C2 서버나 악성 서버의 IP일 가능성이 있습니다. 해당 IP와의 통신을 차단해야 합니다.',
}

export default function AnalysisResult({ data }: AnalysisResultProps) {
  const riskColorClass = getRiskColor(data.risk_level)
  const gaugeColorClass = getRiskGaugeColor(data.risk_score)
  const friendlySummary = getUserFriendlySummary(data)

  // 모든 툴을 표시하기 위해 항상 true로 설정
  const hasSummaryTable = true

  // 각 툴의 상세 설명 토글 상태 관리 (행 클릭용)
  const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({})

  const toggleToolDescription = (toolName: string) => {
    setExpandedTools((prev: Record<string, boolean>) => ({
      ...prev,
      [toolName]: !prev[toolName]
    }))
  }

  return (
    <div className="bg-slate-900/70 rounded-lg shadow-lg p-6 space-y-6 border border-slate-700">
      <div>
        <div className="flex items-center mb-2">
          <SectionIcon type="score" />
          <h2 className="text-2xl font-bold text-slate-50">기술 분석 결과</h2>
        </div>
        <p className="text-sm text-slate-400">
          아래 정보는 파일 자체를 정적으로 분석한 결과이며, 실행 없이 구조와 패턴만을 기반으로 평가합니다.
        </p>
      </div>

      {/* Risk Score */}
      <div className="mb-2">
        <div className="flex justify-between items-center mb-3">
          <div className="flex flex-col">
            <span className="text-sm font-medium text-slate-300 mb-1">위험도 점수</span>
            <span className="text-xs text-slate-400">
              점수가 높을수록 악성일 가능성이 크며, 80점 이상은 즉시 조치가 필요합니다.
            </span>
          </div>
          <span className={`px-4 py-2 rounded-md font-bold text-sm ${riskColorClass}`}>
            {data.risk_score}/100 · {data.risk_level}
          </span>
        </div>
        <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden border border-slate-700">
          <div
            className={`h-3 rounded-full transition-all duration-300 ${gaugeColorClass}`}
            style={{ width: `${data.risk_score}%` }}
          ></div>
        </div>
        <p className="mt-3 text-sm text-slate-200 leading-relaxed">{getRiskDescription(data.risk_level)}</p>
      </div>

      {/* User-friendly summary */}
      {friendlySummary.length > 0 && (
        <div className="border border-cyan-800/50 bg-cyan-900/20 rounded-md p-4">
          <div className="flex items-center mb-2">
            <SectionIcon type="engine" />
            <span className="text-sm font-semibold text-slate-200">분석 요약 (일반 사용자용)</span>
          </div>
          <ul className="mt-1 space-y-1 text-sm text-slate-300 list-disc list-inside">
            {friendlySummary.map((msg, idx) => (
              <li key={idx}>{msg}</li>
            ))}
          </ul>
        </div>
      )}

      {/* ClamAV Result */}
      {data.clamav_result && (
        <div className="mb-4 p-4 bg-red-900/30 border border-red-700/50 rounded-md">
          <span className="font-semibold text-red-300">ClamAV 탐지 결과:</span>
          <span className="ml-2 text-red-200">{data.clamav_result}</span>
        </div>
      )}

      {/* YARA Matches */}
      {data.yara_matches.length > 0 && (
        <div className="mb-4">
          <span className="font-semibold text-slate-200">YARA 탐지 규칙:</span>
          <div className="mt-2 flex flex-wrap gap-2">
            {data.yara_matches.map((match, idx) => (
              <span
                key={idx}
                className="px-3 py-1 bg-yellow-900/40 text-yellow-300 border border-yellow-700/50 rounded-full text-sm"
              >
                {match}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Shellcode Patterns */}
      {data.shellcode_patterns.length > 0 && (
        <div className="mb-4">
          <span className="font-semibold text-slate-200">쉘코드 패턴 발견:</span>
          <ul className="mt-2 space-y-1">
            {data.shellcode_patterns.map((pattern, idx) => (
              <li key={idx} className="text-sm text-red-200 bg-red-900/30 border border-red-700/50 p-2 rounded">
                {pattern}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Suspicious Strings */}
      {data.suspicious_strings.length > 0 && (
        <div className="mb-4">
          <span className="font-semibold text-slate-200">추출된 의심 문자열:</span>
          <ul className="mt-2 space-y-1 max-h-48 overflow-y-auto">
            {data.suspicious_strings.slice(0, 10).map((str, idx) => (
              <li key={idx} className="text-sm text-yellow-200 bg-yellow-900/20 border border-yellow-700/30 p-2 rounded font-mono break-all">
                - {str}
              </li>
            ))}
            {data.suspicious_strings.length > 10 && (
              <li className="text-sm text-slate-400 italic">
                ... 외 {data.suspicious_strings.length - 10}개 더
              </li>
            )}
          </ul>
        </div>
      )}

      {/* Spear-phishing Indicators */}
      {data.spearphishing_indicators && (
        <div className="mb-4 p-4 bg-orange-900/20 border border-orange-700/50 rounded-md">
          <div className="flex items-center mb-1">
            <SectionIcon type="email" />
            <span className="font-semibold text-orange-300">스피어피싱 관련 징후</span>
          </div>
          <p className="text-xs text-orange-200 mb-2">
            이메일 기반 공격 여부를 간단히 보여줍니다. 아래 항목이 하나라도 참이면 메일 본문과 첨부파일을 특히 주의해서
            확인해야 합니다.
          </p>
          <ul className="mt-1 space-y-2 text-sm text-orange-200">
            {data.spearphishing_indicators.spoofed_sender && (
              <li className="flex items-center">
                <span className="mr-2 inline-block h-2 w-2 rounded-full bg-red-400" />
                이메일 발신자 주소가 위조되었을 가능성이 있습니다. 메일 주소 전체를 다시 확인하세요.
              </li>
            )}
            {data.spearphishing_indicators.phishing_keywords &&
              data.spearphishing_indicators.phishing_keywords.length > 0 && (
                <li>
                  피싱 키워드:{' '}
                  <span className="font-semibold">
                    {data.spearphishing_indicators.phishing_keywords.join(', ')}
                  </span>
                </li>
              )}
            {data.spearphishing_indicators.suspicious_urls &&
              data.spearphishing_indicators.suspicious_urls.length > 0 && (
                <li>
                  의심스러운 URL 링크: {data.spearphishing_indicators.suspicious_urls.length}개
                </li>
              )}
            {data.spearphishing_indicators.has_double_extension && (
              <li className="flex items-center">
                <span className="mr-2 inline-block h-2 w-2 rounded-full bg-red-400" />
                이중 확장자(예: invoice.pdf.exe)가 감지되었습니다. 사용자를 속이기 위한 형태일 수 있습니다.
              </li>
            )}
          </ul>
        </div>
      )}

      {/* External API Results */}
      {data.external_apis && (
        <div className="mt-6 pt-4 border-t border-slate-700">
          <h3 className="text-lg font-semibold text-slate-200 mb-4">외부 위협 인텔리전스</h3>
          
          {/* File Hashes */}
          {data.external_apis.file_hashes && (
            <div className="mb-4 p-3 bg-slate-800/50 rounded border border-slate-700">
              <span className="text-sm font-semibold text-slate-300">파일 해시:</span>
              <div className="mt-2 space-y-1 text-xs font-mono text-slate-400">
                {data.external_apis.file_hashes.md5 && (
                  <div>MD5: <span className="text-cyan-300">{data.external_apis.file_hashes.md5}</span></div>
                )}
                {data.external_apis.file_hashes.sha1 && (
                  <div>SHA1: <span className="text-cyan-300">{data.external_apis.file_hashes.sha1}</span></div>
                )}
                {data.external_apis.file_hashes.sha256 && (
                  <div>SHA256: <span className="text-cyan-300">{data.external_apis.file_hashes.sha256}</span></div>
                )}
              </div>
            </div>
          )}

          {/* VirusTotal */}
          {data.external_apis.virustotal && (
            <div className="mb-4 p-4 bg-red-900/30 border border-red-700/50 rounded-md">
              <div className="flex items-center justify-between mb-2">
                <span className="font-semibold text-red-300">VirusTotal 검색 결과</span>
                {data.external_apis.virustotal.permalink && (
                  <a
                    href={data.external_apis.virustotal.permalink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-red-200 hover:text-red-100 underline"
                  >
                    상세 보기 →
                  </a>
                )}
              </div>
              <div className="text-sm text-red-200">
                <span className="font-semibold">{data.external_apis.virustotal.detected}</span> /{' '}
                <span>{data.external_apis.virustotal.total}</span> 엔진이 악성으로 탐지
                {data.external_apis.virustotal.detected > 0 && (
                  <span className="ml-2 text-red-300 font-bold">
                    ({Math.round((data.external_apis.virustotal.detected / data.external_apis.virustotal.total) * 100)}%)
                  </span>
                )}
              </div>
            </div>
          )}

          {/* MalwareBazaar */}
          {data.external_apis.malwarebazaar && (
            <div className="mb-4 p-4 bg-orange-900/30 border border-orange-700/50 rounded-md">
              <span className="font-semibold text-orange-300">MalwareBazaar 샘플 정보</span>
              <div className="mt-2 space-y-1 text-sm text-orange-200">
                {data.external_apis.malwarebazaar.file_name && (
                  <div>파일명: <span className="font-mono">{data.external_apis.malwarebazaar.file_name}</span></div>
                )}
                {data.external_apis.malwarebazaar.signature && (
                  <div>시그니처: <span className="font-semibold">{data.external_apis.malwarebazaar.signature}</span></div>
                )}
                {data.external_apis.malwarebazaar.tags && data.external_apis.malwarebazaar.tags.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {data.external_apis.malwarebazaar.tags.map((tag, idx) => (
                      <span key={idx} className="px-2 py-1 bg-orange-800/50 rounded text-xs">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
                {data.external_apis.malwarebazaar.first_seen && (
                  <div className="text-xs text-orange-300 mt-2">
                    최초 발견: {data.external_apis.malwarebazaar.first_seen}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* URL Scans */}
          {data.external_apis.url_scans && data.external_apis.url_scans.length > 0 && (
            <div className="mb-4">
              <span className="font-semibold text-slate-200">URL 스캔 결과:</span>
              <div className="mt-2 space-y-2">
                {data.external_apis.url_scans.map((scan, idx) => (
                  <div
                    key={idx}
                    className={`p-3 rounded border ${
                      scan.malicious
                        ? 'bg-red-900/30 border-red-700/50'
                        : 'bg-slate-800/50 border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <a
                        href={scan.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-cyan-300 hover:text-cyan-200 underline break-all"
                      >
                        {scan.url}
                      </a>
                      {scan.malicious && (
                        <span className="px-2 py-1 bg-red-600 text-white text-xs rounded font-semibold">
                          악성
                        </span>
                      )}
                    </div>
                    <div className="mt-1 text-xs text-slate-400">
                      도메인: {scan.domain} | 위협 점수: {scan.threat_score}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* IP Information */}
          {data.external_apis.ip_info && data.external_apis.ip_info.length > 0 && (
            <div className="mb-4">
              <span className="font-semibold text-slate-200">IP 주소 정보:</span>
              <div className="mt-2 space-y-2">
                {data.external_apis.ip_info.map((ip, idx) => (
                  <div key={idx} className="p-3 bg-slate-800/50 rounded border border-slate-700">
                    <div className="text-sm font-mono text-cyan-300">{ip.ip}</div>
                    <div className="text-xs text-slate-400 mt-1">
                      {ip.country} {ip.city && `· ${ip.city}`} | ISP: {ip.isp}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 엔진별 / 외부 API 요약 표 */}
      {hasSummaryTable && (
        <div className="mt-6 pt-4 border-t border-slate-700">
          <h3 className="text-lg font-semibold text-slate-200 mb-3">엔진·외부 서비스별 요약</h3>
          <p className="text-xs text-slate-400 mb-2">
            각 분석 엔진과 외부 보안 서비스가 어떻게 판단했는지 한눈에 볼 수 있습니다.
          </p>
          <div className="overflow-x-auto rounded-lg border border-slate-700 bg-slate-900/60">
            <table className="min-w-full text-xs text-left text-slate-200">
              <thead className="bg-slate-800/80">
                <tr>
                  <th className="px-4 py-2 border-b border-slate-700">구분</th>
                  <th className="px-4 py-2 border-b border-slate-700">도구 / 서비스</th>
                  <th className="px-4 py-2 border-b border-slate-700">결과 요약</th>
                </tr>
              </thead>
              <tbody>
                {/* ClamAV */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('ClamAV')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">ClamAV</span>
                    {expandedTools['ClamAV'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['ClamAV']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.clamav_result ? 'text-red-300' : 'text-green-300'}`}>
                    {data.clamav_result
                      ? `악성 시그니처 탐지: ${data.clamav_result}`
                      : '탐지 없음'}
                  </td>
                </tr>

                {/* YARA */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('YARA 규칙')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">YARA 규칙</span>
                    {expandedTools['YARA 규칙'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['YARA 규칙']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.yara_matches.length > 0 ? 'text-orange-300' : 'text-green-300'}`}>
                    {data.yara_matches.length > 0
                      ? `${data.yara_matches.length}개 규칙에서 의심 패턴 감지`
                      : '탐지 없음'}
                  </td>
                </tr>

                {/* 엔트로피 분석 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('엔트로피 분석')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">엔트로피 분석</span>
                    {expandedTools['엔트로피 분석'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['엔트로피 분석']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.entropy !== undefined ? (data.entropy > 7.0 ? 'text-orange-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.entropy !== undefined
                      ? data.entropy > 7.5
                        ? `매우 높은 엔트로피 (${data.entropy.toFixed(2)}/8.0) - 패킹/암호화 가능성 높음`
                        : data.entropy > 7.0
                        ? `높은 엔트로피 (${data.entropy.toFixed(2)}/8.0) - 패킹 가능성`
                        : `정상 범위 (${data.entropy.toFixed(2)}/8.0)`
                      : '분석 안 됨'}
                  </td>
                </tr>

                {/* 파일 타입 검증 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('파일 타입 검증')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">파일 타입 검증</span>
                    {expandedTools['파일 타입 검증'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['파일 타입 검증']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.file_type_analysis ? (data.file_type_analysis.suspicious || !data.file_type_analysis.extension_match ? 'text-red-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.file_type_analysis
                      ? data.file_type_analysis.suspicious || !data.file_type_analysis.extension_match
                        ? `확장자 위조 의심 (실제 타입: ${data.file_type_analysis.actual_type || '알 수 없음'})`
                        : '확장자 일치 (정상)'
                      : '분석 안 됨'}
                  </td>
                </tr>

                {/* PE 강화 분석 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('PE 강화 분석')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">PE 강화 분석</span>
                    {expandedTools['PE 강화 분석'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['PE 강화 분석']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.pe_enhanced ? (data.pe_enhanced.suspicious_characteristics && data.pe_enhanced.suspicious_characteristics.length > 0 ? 'text-orange-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.pe_enhanced
                      ? data.pe_enhanced.suspicious_characteristics && data.pe_enhanced.suspicious_characteristics.length > 0
                        ? `의심스러운 특성 ${data.pe_enhanced.suspicious_characteristics.length}개 발견`
                        : '이상 없음'
                      : 'PE 파일 아님 또는 분석 안 됨'}
                  </td>
                </tr>

                {/* 쉘코드 탐지 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('쉘코드 탐지')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">쉘코드 탐지</span>
                    {expandedTools['쉘코드 탐지'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['쉘코드 탐지']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.shellcode_patterns.length > 0 ? 'text-red-300' : 'text-green-300'}`}>
                    {data.shellcode_patterns.length > 0
                      ? `프로세스 제어를 시도하는 코드 패턴 ${data.shellcode_patterns.length}개 발견`
                      : '탐지 없음'}
                  </td>
                </tr>

                {/* 의심 문자열 분석 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('의심 문자열 분석')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">의심 문자열 분석</span>
                    {expandedTools['의심 문자열 분석'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['의심 문자열 분석']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.suspicious_strings.length > 0 ? 'text-orange-300' : 'text-green-300'}`}>
                    {data.suspicious_strings.length > 0
                      ? `의심스러운 문자열 ${data.suspicious_strings.length}개 추출`
                      : '추출 없음'}
                  </td>
                </tr>

                {/* Office 문서 분석 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('Office 문서 분석')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">Office 문서 분석</span>
                    {expandedTools['Office 문서 분석'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['Office 문서 분석']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.office_analysis ? (data.office_analysis.auto_exec_macros ? 'text-red-300' : data.office_analysis.has_macros ? 'text-orange-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.office_analysis
                      ? data.office_analysis.auto_exec_macros
                        ? `자동 실행 매크로 발견 (${data.office_analysis.macro_count || 0}개 매크로)`
                        : data.office_analysis.has_macros
                        ? `VBA 매크로 발견 (${data.office_analysis.macro_count || 0}개)`
                        : '매크로 없음'
                      : 'Office 파일 아님 또는 분석 안 됨'}
                  </td>
                </tr>

                {/* PDF 분석 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('PDF 분석')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">PDF 분석</span>
                    {expandedTools['PDF 분석'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['PDF 분석']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.pdf_analysis ? (data.pdf_analysis.has_javascript ? 'text-red-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.pdf_analysis
                      ? data.pdf_analysis.has_javascript
                        ? `JavaScript 포함 (의심스러운 객체 ${data.pdf_analysis.suspicious_objects?.length || 0}개)`
                        : '이상 없음'
                      : 'PDF 파일 아님 또는 분석 안 됨'}
                  </td>
                </tr>

                {/* ZIP 분석 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('ZIP 분석')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">ZIP 분석</span>
                    {expandedTools['ZIP 분석'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['ZIP 분석']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.zip_analysis ? (data.zip_analysis.suspicious_files && data.zip_analysis.suspicious_files.length > 0 ? 'text-red-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.zip_analysis
                      ? data.zip_analysis.suspicious_files && data.zip_analysis.suspicious_files.length > 0
                        ? `의심스러운 파일 ${data.zip_analysis.suspicious_files.length}개 발견 (내부 파일 ${data.zip_analysis.file_count || 0}개)`
                        : '이상 없음'
                      : 'ZIP 파일 아님 또는 분석 안 됨'}
                  </td>
                </tr>

                {/* 스피어피싱 지표 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('스피어피싱 지표')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">스피어피싱 지표</span>
                    {expandedTools['스피어피싱 지표'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['스피어피싱 지표']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.spearphishing_indicators && (data.spearphishing_indicators.spoofed_sender || data.spearphishing_indicators.phishing_keywords?.length > 0 || data.spearphishing_indicators.suspicious_urls?.length > 0 || data.spearphishing_indicators.has_double_extension) ? 'text-orange-300' : 'text-green-300'}`}>
                    {data.spearphishing_indicators && (data.spearphishing_indicators.spoofed_sender || data.spearphishing_indicators.phishing_keywords?.length > 0 || data.spearphishing_indicators.suspicious_urls?.length > 0 || data.spearphishing_indicators.has_double_extension)
                      ? '이메일 기반 공격 징후 발견'
                      : '탐지 없음'}
                  </td>
                </tr>

                {/* 파일 해시 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('파일 해시')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">파일 해시</span>
                    {expandedTools['파일 해시'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['파일 해시']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.file_hashes?.sha256 ? 'text-green-300' : 'text-slate-400'}`}>
                    {data.file_hashes?.sha256
                      ? `SHA256: ${data.file_hashes.sha256.substring(0, 16)}... (계산 완료)`
                      : '계산 안 됨'}
                  </td>
                </tr>

                {/* 파일 크기 분석 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('파일 크기 분석')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">파일 크기 분석</span>
                    {expandedTools['파일 크기 분석'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['파일 크기 분석']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.file_size_analysis ? (data.file_size_analysis.suspicious ? 'text-orange-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.file_size_analysis
                      ? data.file_size_analysis.suspicious
                        ? `이상 크기 (${data.file_size_analysis.size_mb}MB) - ${data.file_size_analysis.anomalies?.length || 0}개 이상 징후`
                        : `정상 크기 (${data.file_size_analysis.size_mb}MB)`
                      : '분석 안 됨'}
                  </td>
                </tr>

                {/* 파일명 패턴 분석 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('파일명 패턴 분석')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">파일명 패턴 분석</span>
                    {expandedTools['파일명 패턴 분석'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['파일명 패턴 분석']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.filename_pattern_analysis ? (data.filename_pattern_analysis.suspicious ? 'text-orange-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.filename_pattern_analysis
                      ? data.filename_pattern_analysis.suspicious
                        ? `의심스러운 패턴 발견 (${data.filename_pattern_analysis.anomalies?.length || 0}개 이상 징후)`
                        : '이상 없음'
                      : '분석 안 됨'}
                  </td>
                </tr>

                {/* Base64 인코딩 탐지 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('Base64 인코딩 탐지')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">내부 엔진</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">Base64 인코딩 탐지</span>
                    {expandedTools['Base64 인코딩 탐지'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['Base64 인코딩 탐지']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.base64_analysis ? (data.base64_analysis.suspicious ? 'text-orange-300' : data.base64_analysis.has_base64 ? 'text-yellow-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.base64_analysis
                      ? data.base64_analysis.suspicious
                        ? `의심스러운 Base64 인코딩 발견 (${data.base64_analysis.anomalies?.length || 0}개 이상 징후)`
                        : data.base64_analysis.has_base64
                        ? `Base64 인코딩 문자열 발견 (${data.base64_analysis.base64_strings?.length || 0}개)`
                        : 'Base64 인코딩 없음'
                      : '분석 안 됨'}
                  </td>
                </tr>

                {/* VirusTotal */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('VirusTotal')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">외부 서비스</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">VirusTotal</span>
                    {expandedTools['VirusTotal'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['VirusTotal']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.external_apis?.virustotal ? (data.external_apis.virustotal.detected > 0 ? 'text-red-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.external_apis?.virustotal
                      ? data.external_apis.virustotal.detected > 0
                        ? `${data.external_apis.virustotal.detected} / ${data.external_apis.virustotal.total} 엔진이 악성으로 탐지 (${Math.round((data.external_apis.virustotal.detected / data.external_apis.virustotal.total) * 100)}% 탐지)`
                        : '탐지 없음'
                      : '조회 안 됨'}
                  </td>
                </tr>

                {/* MalwareBazaar */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('MalwareBazaar')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">외부 서비스</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">MalwareBazaar</span>
                    {expandedTools['MalwareBazaar'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['MalwareBazaar']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.external_apis?.malwarebazaar ? (data.external_apis.malwarebazaar.signature ? 'text-red-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.external_apis?.malwarebazaar
                      ? data.external_apis.malwarebazaar.signature
                        ? `알려진 악성 샘플 시그니처: ${data.external_apis.malwarebazaar.signature}`
                        : '샘플 없음'
                      : '조회 안 됨'}
                  </td>
                </tr>

                {/* URL 스캔 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('URL 스캔')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">외부 서비스</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">URL 스캔</span>
                    {expandedTools['URL 스캔'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['URL 스캔']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.external_apis?.url_scans && data.external_apis.url_scans.length > 0 ? (data.external_apis.url_scans.some(s => s.malicious) ? 'text-red-300' : 'text-green-300') : 'text-slate-400'}`}>
                    {data.external_apis?.url_scans && data.external_apis.url_scans.length > 0
                      ? `파일 내부 URL ${data.external_apis.url_scans.length}개 분석 (악성 ${data.external_apis.url_scans.filter(s => s.malicious).length}개)`
                      : 'URL 없음'}
                  </td>
                </tr>

                {/* IP 정보 조회 */}
                <tr 
                  className="hover:bg-slate-800/40 cursor-pointer"
                  onClick={() => toggleToolDescription('IP 정보 조회')}
                >
                  <td className="px-4 py-2 border-b border-slate-800 text-slate-300">외부 서비스</td>
                  <td className="px-4 py-2 border-b border-slate-800">
                    <span className="font-semibold text-cyan-300">IP 정보 조회</span>
                    {expandedTools['IP 정보 조회'] && (
                      <div className="mt-2 p-3 bg-slate-700/80 rounded border border-cyan-500/50 text-xs text-slate-200 leading-relaxed whitespace-pre-line">
                        {toolDetailedDescriptions['IP 정보 조회']}
                      </div>
                    )}
                  </td>
                  <td className={`px-4 py-2 border-b border-slate-800 ${data.external_apis?.ip_info && data.external_apis.ip_info.length > 0 ? 'text-green-300' : 'text-slate-400'}`}>
                    {data.external_apis?.ip_info && data.external_apis.ip_info.length > 0
                      ? `IP 주소 ${data.external_apis.ip_info.length}개 정보 조회 완료`
                      : 'IP 없음'}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Analysis Timeline */}
      <div className="mt-6 pt-4 border-t border-slate-700">
        <div className="flex items-center text-sm text-slate-400">
          <SectionIcon type="timeline" />
          <p>
            분석 완료 시간: <span className="font-medium text-slate-300">{new Date().toLocaleString('ko-KR')}</span>
          </p>
        </div>
        <p className="mt-1 text-xs text-slate-500">
          업로드된 파일은 1시간 후 자동으로 삭제되며, 분석 결과만 안전하게 보관됩니다.
        </p>
      </div>
    </div>
  )
}

