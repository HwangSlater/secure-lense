'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import AnalysisResult from '@/components/AnalysisResult'
import URLResult from '@/components/URLResult'
import AIInsight from '@/components/AIInsight'

interface AnalysisData {
  scan_id: string
  filename: string
  risk_score: number
  risk_level: string
  clamav_result: string | null
  yara_matches: string[]
  shellcode_patterns: string[]
  suspicious_strings: string[]
  spearphishing_indicators: any
  ai_analysis?: string | null
  file_deleted_at: string
  uploaded_at: string
  // URL analysis fields
  url?: string
  urlscan?: any
  ip_info?: any
  domain_info?: any
  analyzed_at?: string
  // External APIs
  external_apis?: any
  url_analysis_result?: any
}

interface PageProps {
  params: {
    scanId: string
  }
}

export default function ResultPage({ params }: PageProps) {
  const router = useRouter()
  const { scanId } = params

  const [data, setData] = useState<AnalysisData | null>(null)
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState<'analysis' | 'url' | 'info'>('analysis')

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) {
      router.push('/login')
      return
    }

    const fetchDetail = async () => {
      try {
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || ''}/analysis/${scanId}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        )

        const json = await response.json()

        if (!response.ok) {
          throw new Error(json.detail || '분석 결과를 불러오는 중 오류가 발생했습니다.')
        }

        setData(json)
        // 서버에 저장된 AI 심층 분석 결과가 있으면 함께 세팅
        if (json.ai_analysis) {
          setAiAnalysis(json.ai_analysis)
        }
        // URL 분석 결과가 있으면 URL 탭을 기본으로 설정
        if (json.url || json.url_analysis_result) {
          setActiveTab('url')
        }
      } catch (err: any) {
        setError(err.message || '분석 결과를 불러오는 중 오류가 발생했습니다.')
      } finally {
        setLoading(false)
      }
    }

    fetchDetail()
  }, [router, scanId])

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-slate-100">분석 결과를 불러오는 중입니다...</p>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="bg-slate-900/80 border border-slate-700 rounded-xl shadow-2xl p-6 max-w-md text-center text-slate-100">
          <p className="mb-4 text-sm">
            {error ||
              '분석 결과를 찾을 수 없습니다. 업로드 후 일정 시간이 지나 자동 삭제되었을 수 있습니다.'}
          </p>
          <Link href="/dashboard" className="text-cyan-300 hover:text-cyan-200 underline text-sm">
            대시보드로 돌아가기
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-transparent">
      <header className="bg-slate-900/70 border-b border-slate-800 backdrop-blur-sm">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between text-slate-100">
          <Link href="/" className="text-xl font-extrabold logo-gradient">
            SecureLens
          </Link>
          <div className="flex items-center space-x-4 text-sm">
            <Link href="/dashboard" className="text-slate-200 hover:text-white">
              대시보드
            </Link>
            <Link href="/mypage" className="text-slate-200 hover:text-white">
              마이페이지
            </Link>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-50 mb-2">분석 결과</h1>
          {data.url ? (
            <p className="text-sm text-slate-200">
              URL: <span className="font-medium">{data.url}</span>
            </p>
          ) : (
            <p className="text-sm text-slate-200">
              파일명: <span className="font-medium">{data.filename}</span>
            </p>
          )}
          <p className="text-xs text-slate-400 mt-1">
            {data.analyzed_at
              ? `분석 시각: ${new Date(data.analyzed_at).toLocaleString('ko-KR')}`
              : `업로드 시각: ${new Date(data.uploaded_at).toLocaleString('ko-KR')}`}
          </p>
        </div>

        {/* 탭 네비게이션 */}
        <div className="border-b border-slate-700">
          <nav className="flex space-x-8">
            {!data.url && (
              <button
                onClick={() => setActiveTab('analysis')}
                className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === 'analysis'
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-300'
                }`}
              >
                분석
              </button>
            )}
            {(data.url || data.url_analysis_result) && (
              <button
                onClick={() => setActiveTab('url')}
                className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === 'url'
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-300'
                }`}
              >
                URL 분석
              </button>
            )}
            <button
              onClick={() => setActiveTab('info')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'info'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-300'
              }`}
            >
              정보
            </button>
          </nav>
        </div>

        {/* 탭 컨텐츠 */}
        {activeTab === 'analysis' && !data.url && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <AnalysisResult data={data} />
            <AIInsight
              scanId={data.scan_id}
              riskScore={data.risk_score}
              riskLevel={data.risk_level}
              filename={data.filename}
              aiAnalysis={aiAnalysis}
              onAnalysisLoaded={setAiAnalysis}
            />
          </div>
        )}

        {activeTab === 'url' && (data.url || data.url_analysis_result) && (
          <div className="space-y-6">
            {data.url ? (
              <URLResult data={data as any} />
            ) : data.url_analysis_result ? (
              <URLResult data={data.url_analysis_result} />
            ) : null}
            <div className="bg-slate-900/70 rounded-lg shadow-lg p-6 border border-slate-700">
              <h2 className="text-xl font-bold mb-4 text-slate-50">URL 분석 안내</h2>
              <div className="space-y-3 text-sm text-slate-300">
                <p>
                  URL 분석은 URLScan.io를 통해 실시간으로 수행됩니다. 악성 URL로 탐지된 경우 즉시 접속을 중단하세요.
                </p>
                {(data.urlscan?.malicious || data.url_analysis_result?.urlscan_result?.verdicts?.overall?.malicious) && (
                  <div className="p-3 bg-red-900/30 border border-red-700/50 rounded">
                    <p className="text-red-300 font-semibold">
                      ⚠️ 이 URL은 악성으로 탐지되었습니다. 접속하지 마세요.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'info' && (
          <div className="bg-slate-900/70 rounded-lg shadow-lg p-6 border border-slate-700">
            <h2 className="text-2xl font-bold mb-6 text-slate-50">SecureLens 서비스 정보</h2>
            <div className="space-y-6">
              {/* 서비스 소개 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">서비스 소개</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 text-sm text-slate-300 leading-relaxed">
                  <p className="mb-3">
                    SecureLens는 파일과 URL을 분석하여 악성코드 및 피싱 공격을 탐지하는 보안 분석 서비스입니다.
                  </p>
                  <p>
                    다중 엔진 스캔, AI 기반 심층 분석, 외부 위협 인텔리전스 연동을 통해 종합적인 보안 분석을 제공합니다.
                  </p>
                </div>
              </div>

              {/* 주요 기능 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">주요 기능</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 space-y-3 text-sm">
                  <div>
                    <span className="font-semibold text-cyan-300">파일 분석</span>
                    <ul className="mt-1 ml-4 list-disc text-slate-300 space-y-1">
                      <li>ClamAV 바이러스 탐지</li>
                      <li>YARA 규칙 기반 패턴 매칭</li>
                      <li>PE 파일 헤더 이상 탐지</li>
                      <li>쉘코드 및 의심스러운 문자열 탐지</li>
                      <li>이메일 스피어피싱 지표 분석</li>
                    </ul>
                  </div>
                  <div>
                    <span className="font-semibold text-cyan-300">URL 분석</span>
                    <ul className="mt-1 ml-4 list-disc text-slate-300 space-y-1">
                      <li>URLScan.io 실시간 스캔</li>
                      <li>악성 URL 탐지 및 위협 점수 평가</li>
                      <li>IP 정보 및 지리적 위치 확인</li>
                    </ul>
                  </div>
                  <div>
                    <span className="font-semibold text-cyan-300">외부 위협 인텔리전스</span>
                    <ul className="mt-1 ml-4 list-disc text-slate-300 space-y-1">
                      <li>VirusTotal: 다수의 백신 엔진 탐지 결과</li>
                      <li>MalwareBazaar: 알려진 악성코드 샘플 데이터베이스</li>
                      <li>파일 해시 기반 위협 검증</li>
                    </ul>
                  </div>
                  <div>
                    <span className="font-semibold text-cyan-300">AI 심층 분석</span>
                    <ul className="mt-1 ml-4 list-disc text-slate-300 space-y-1">
                      <li>Google Gemini 기반 상세 분석</li>
                      <li>일반인도 이해하기 쉬운 설명</li>
                      <li>구체적인 대응 방법 제시</li>
                    </ul>
                  </div>
                </div>
              </div>

              {/* 위험도 점수 설명 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">위험도 점수 기준</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 space-y-2 text-sm">
                  <div className="flex items-center space-x-3">
                    <span className="px-3 py-1 bg-green-700 text-white rounded text-xs font-semibold">0-30</span>
                    <span className="text-slate-300">매우 낮음: 안전한 파일로 판단됩니다.</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="px-3 py-1 bg-yellow-700 text-white rounded text-xs font-semibold">31-50</span>
                    <span className="text-slate-300">낮음: 주의가 필요할 수 있습니다.</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="px-3 py-1 bg-orange-700 text-white rounded text-xs font-semibold">51-70</span>
                    <span className="text-slate-300">보통: 의심스러운 파일입니다. 신중히 검토하세요.</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="px-3 py-1 bg-red-700 text-white rounded text-xs font-semibold">71-85</span>
                    <span className="text-slate-300">높음: 악성 파일일 가능성이 높습니다.</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="px-3 py-1 bg-red-900 text-white rounded text-xs font-semibold">86-100</span>
                    <span className="text-slate-300">매우 높음: 즉시 삭제하고 조치가 필요합니다.</span>
                  </div>
                </div>
              </div>

              {/* 사용 팁 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">사용 팁</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 space-y-2 text-sm text-slate-300">
                  <p>• 이메일 파일(.eml) 분석 시, 제목과 내용을 추가하면 더 정확한 분석이 가능합니다.</p>
                  <p>• AI 심층 분석은 분석 티켓이 필요하며, 더 상세한 설명과 대응 방법을 제공합니다.</p>
                  <p>• 업로드된 파일은 1시간 후 자동으로 삭제됩니다.</p>
                  <p>• 시간당 최대 10개의 파일을 업로드할 수 있습니다.</p>
                </div>
              </div>

              {/* 문의 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">문의 및 지원</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 text-sm text-slate-300">
                  <p>서비스 관련 문의사항이나 문제가 발생한 경우, 관리자에게 문의해주세요.</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}


