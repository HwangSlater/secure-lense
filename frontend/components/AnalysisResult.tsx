'use client'

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

export default function AnalysisResult({ data }: AnalysisResultProps) {
  const riskColorClass = getRiskColor(data.risk_level)
  const gaugeColorClass = getRiskGaugeColor(data.risk_score)
  const friendlySummary = getUserFriendlySummary(data)

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

