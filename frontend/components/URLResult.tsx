'use client'

interface URLResultProps {
  data: {
    scan_id: string
    url: string
    risk_score: number
    risk_level: string
    urlscan?: {
      url: string
      domain: string
      ip?: string
      country?: string
      malicious: boolean
      threat_score: number
      tags: string[]
      screenshot?: string
      uuid?: string
    }
    ip_info?: {
      ip: string
      country: string
      city: string
      isp: string
      org?: string
    }
    domain_info?: {
      domain: string
      resolved_ip?: string
    }
    analyzed_at: string
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

export default function URLResult({ data }: URLResultProps) {
  const riskColorClass = getRiskColor(data.risk_level)
  const gaugeColorClass = getRiskGaugeColor(data.risk_score)

  return (
    <div className="bg-slate-900/70 rounded-lg shadow-lg p-6 space-y-6 border border-slate-700">
      <div>
        <h2 className="text-2xl font-bold mb-2 text-slate-50">URL 분석 결과</h2>
        <p className="text-sm text-slate-400">
          분석 시각: {new Date(data.analyzed_at).toLocaleString('ko-KR')}
        </p>
      </div>

      {/* URL */}
      <div>
        <span className="text-sm font-medium text-slate-300 mb-2 block">분석된 URL</span>
        <a
          href={data.url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-cyan-300 hover:text-cyan-200 underline break-all text-sm"
        >
          {data.url}
        </a>
      </div>

      {/* Risk Score */}
      <div>
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
      </div>

      {/* URLScan Results */}
      {data.urlscan && (
        <div className={`p-4 rounded-md border ${
          data.urlscan.malicious
            ? 'bg-red-900/30 border-red-700/50'
            : 'bg-slate-800/50 border-slate-700'
        }`}>
          <div className="flex items-center justify-between mb-3">
            <span className="font-semibold text-slate-200">URLScan.io 분석 결과</span>
            {data.urlscan.uuid && (
              <a
                href={`https://urlscan.io/result/${data.urlscan.uuid}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-cyan-300 hover:text-cyan-200 underline"
              >
                상세 보기 →
              </a>
            )}
          </div>
          
          {data.urlscan.malicious && (
            <div className="mb-3 p-2 bg-red-800/50 rounded border border-red-600/50">
              <span className="text-red-300 font-semibold">⚠️ 악성 URL로 탐지됨</span>
            </div>
          )}

          <div className="space-y-2 text-sm">
            <div>
              <span className="text-slate-400">도메인:</span>{' '}
              <span className="text-slate-200">{data.urlscan.domain}</span>
            </div>
            {data.urlscan.ip && (
              <div>
                <span className="text-slate-400">IP 주소:</span>{' '}
                <span className="text-slate-200 font-mono">{data.urlscan.ip}</span>
              </div>
            )}
            {data.urlscan.country && (
              <div>
                <span className="text-slate-400">국가:</span>{' '}
                <span className="text-slate-200">{data.urlscan.country}</span>
              </div>
            )}
            <div>
              <span className="text-slate-400">위협 점수:</span>{' '}
              <span className={`font-semibold ${
                data.urlscan.threat_score > 50 ? 'text-red-300' : 
                data.urlscan.threat_score > 20 ? 'text-orange-300' : 'text-yellow-300'
              }`}>
                {data.urlscan.threat_score}/100
              </span>
            </div>
            {data.urlscan.tags && data.urlscan.tags.length > 0 && (
              <div>
                <span className="text-slate-400">태그:</span>
                <div className="flex flex-wrap gap-2 mt-1">
                  {data.urlscan.tags.map((tag, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-1 bg-slate-700/50 rounded text-xs text-slate-300"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {data.urlscan.screenshot && (
              <div className="mt-3">
                <a
                  href={data.urlscan.screenshot}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyan-300 hover:text-cyan-200 underline text-xs"
                >
                  스크린샷 보기 →
                </a>
              </div>
            )}
          </div>
        </div>
      )}

      {/* IP Information */}
      {data.ip_info && (
        <div className="p-4 bg-slate-800/50 rounded border border-slate-700">
          <span className="font-semibold text-slate-200 mb-3 block">IP 주소 정보</span>
          <div className="space-y-2 text-sm">
            <div>
              <span className="text-slate-400">IP:</span>{' '}
              <span className="text-slate-200 font-mono">{data.ip_info.ip}</span>
            </div>
            <div>
              <span className="text-slate-400">위치:</span>{' '}
              <span className="text-slate-200">
                {data.ip_info.country}
                {data.ip_info.city && `, ${data.ip_info.city}`}
              </span>
            </div>
            <div>
              <span className="text-slate-400">ISP:</span>{' '}
              <span className="text-slate-200">{data.ip_info.isp}</span>
            </div>
            {data.ip_info.org && (
              <div>
                <span className="text-slate-400">조직:</span>{' '}
                <span className="text-slate-200">{data.ip_info.org}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Domain Information */}
      {data.domain_info && (
        <div className="p-4 bg-slate-800/50 rounded border border-slate-700">
          <span className="font-semibold text-slate-200 mb-3 block">도메인 정보</span>
          <div className="space-y-2 text-sm">
            <div>
              <span className="text-slate-400">도메인:</span>{' '}
              <span className="text-slate-200">{data.domain_info.domain}</span>
            </div>
            {data.domain_info.resolved_ip && (
              <div>
                <span className="text-slate-400">해석된 IP:</span>{' '}
                <span className="text-slate-200 font-mono">{data.domain_info.resolved_ip}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

