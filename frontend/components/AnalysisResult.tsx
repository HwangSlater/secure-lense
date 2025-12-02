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
  }
}

const getRiskColor = (riskLevel: string) => {
  switch (riskLevel) {
    case '매우 낮음':
      return 'text-green-600 bg-green-50'
    case '낮음':
      return 'text-yellow-600 bg-yellow-50'
    case '보통':
      return 'text-orange-600 bg-orange-50'
    case '높음':
      return 'text-red-600 bg-red-50'
    case '매우 높음':
      return 'text-red-800 bg-red-100'
    default:
      return 'text-gray-600 bg-gray-50'
  }
}

const getRiskGaugeColor = (score: number) => {
  if (score <= 20) return 'bg-green-500'
  if (score <= 40) return 'bg-yellow-500'
  if (score <= 60) return 'bg-orange-500'
  if (score <= 80) return 'bg-red-500'
  return 'bg-red-700'
}

export default function AnalysisResult({ data }: AnalysisResultProps) {
  const riskColorClass = getRiskColor(data.risk_level)
  const gaugeColorClass = getRiskGaugeColor(data.risk_score)

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <h2 className="text-2xl font-bold mb-6 text-gray-800">기술 분석 결과</h2>

      {/* Risk Score */}
      <div className="mb-6">
        <div className="flex justify-between items-center mb-2">
          <span className="text-lg font-semibold text-gray-700">위험도 점수:</span>
          <span className={`px-4 py-2 rounded-md font-bold ${riskColorClass}`}>
            {data.risk_score}/100 {data.risk_level}
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-4">
          <div
            className={`h-4 rounded-full transition-all duration-300 ${gaugeColorClass}`}
            style={{ width: `${data.risk_score}%` }}
          ></div>
        </div>
      </div>

      {/* ClamAV Result */}
      {data.clamav_result && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
          <span className="font-semibold text-red-800">🦠 ClamAV 탐지:</span>
          <span className="ml-2 text-red-700">{data.clamav_result}</span>
        </div>
      )}

      {/* YARA Matches */}
      {data.yara_matches.length > 0 && (
        <div className="mb-4">
          <span className="font-semibold text-gray-700">🎯 YARA 탐지 규칙:</span>
          <div className="mt-2 flex flex-wrap gap-2">
            {data.yara_matches.map((match, idx) => (
              <span
                key={idx}
                className="px-3 py-1 bg-yellow-100 text-yellow-800 rounded-full text-sm"
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
          <span className="font-semibold text-gray-700">💉 쉘코드 발견:</span>
          <ul className="mt-2 space-y-1">
            {data.shellcode_patterns.map((pattern, idx) => (
              <li key={idx} className="text-sm text-gray-600 bg-red-50 p-2 rounded">
                {pattern}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Suspicious Strings */}
      {data.suspicious_strings.length > 0 && (
        <div className="mb-4">
          <span className="font-semibold text-gray-700">🔍 추출된 의심 문자열:</span>
          <ul className="mt-2 space-y-1 max-h-48 overflow-y-auto">
            {data.suspicious_strings.slice(0, 10).map((str, idx) => (
              <li key={idx} className="text-sm text-gray-600 bg-yellow-50 p-2 rounded font-mono break-all">
                - {str}
              </li>
            ))}
            {data.suspicious_strings.length > 10 && (
              <li className="text-sm text-gray-500 italic">
                ... 외 {data.suspicious_strings.length - 10}개 더
              </li>
            )}
          </ul>
        </div>
      )}

      {/* Spear-phishing Indicators */}
      {data.spearphishing_indicators && (
        <div className="mb-4 p-4 bg-orange-50 border border-orange-200 rounded-md">
          <span className="font-semibold text-orange-800">🎣 스피어피싱 지표:</span>
          <ul className="mt-2 space-y-2 text-sm text-orange-700">
            {data.spearphishing_indicators.spoofed_sender && (
              <li className="flex items-center">
                <span className="text-red-500 mr-2">✓</span>
                발신자 위조 감지
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
                  의심스러운 URL: {data.spearphishing_indicators.suspicious_urls.length}개
                </li>
              )}
            {data.spearphishing_indicators.has_double_extension && (
              <li className="flex items-center">
                <span className="text-red-500 mr-2">✓</span>
                이중 확장자 감지
              </li>
            )}
          </ul>
        </div>
      )}

      {/* Analysis Timeline */}
      <div className="mt-6 pt-4 border-t border-gray-200">
        <p className="text-sm text-gray-500">분석 완료: {new Date().toLocaleString('ko-KR')}</p>
      </div>
    </div>
  )
}

