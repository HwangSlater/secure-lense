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
  const [activeTab, setActiveTab] = useState<'analysis' | 'ai'>('analysis')

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

        // Check if response is JSON
        let json
        try {
          json = await response.json()
        } catch (parseErr) {
          if (response.status === 404) {
            setError('분석 결과를 찾을 수 없습니다. 업로드 후 일정 시간이 지나 자동 삭제되었을 수 있습니다.')
            return
          } else if (response.status >= 500) {
            setError('서버에서 문제가 발생했습니다. 잠시 후 다시 시도해주세요.')
            return
          } else {
            setError('분석 결과를 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
            return
          }
        }

        if (!response.ok) {
          const errorMessage = json.detail || json.message || '분석 결과를 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.'
          setError(errorMessage)
          return
        }

        setData(json)
        // 서버에 저장된 AI 심층 분석 결과가 있으면 함께 세팅
        if (json.ai_analysis) {
          setAiAnalysis(json.ai_analysis)
        }
      } catch (err: any) {
        // Show user-friendly error message
        let errorMessage = '분석 결과를 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.'
        
        if (err.message && !err.message.includes('<!DOCTYPE') && !err.message.includes('Error:')) {
          errorMessage = err.message
        } else if (err.name === 'TypeError' && err.message.includes('fetch')) {
          errorMessage = '서버에 연결할 수 없습니다. 네트워크 연결을 확인해주세요.'
        }
        
        setError(errorMessage)
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
        {(() => {
          // Check if this is a URL analysis (filename starts with http:// or https://, or has url field)
          const isUrlAnalysis = data.url || (data.filename && (data.filename.startsWith('http://') || data.filename.startsWith('https://')))
          const displayUrl = data.url || (isUrlAnalysis ? data.filename : null)

          if (isUrlAnalysis) {
            // URL Analysis Result
            return (
              <>
                <div>
                  <h1 className="text-2xl font-bold text-slate-50 mb-2">URL 분석 결과</h1>
                  <p className="text-sm text-slate-200">
                    URL: <span className="font-medium break-all">{displayUrl}</span>
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    {data.analyzed_at
                      ? `분석 시각: ${new Date(data.analyzed_at).toLocaleString('ko-KR')}`
                      : `분석 시각: ${new Date(data.uploaded_at).toLocaleString('ko-KR')}`}
                  </p>
                </div>

                <div className="space-y-6">
                  {data.url ? (
                    <URLResult data={data as any} />
                  ) : data.url_analysis_result ? (
                    <URLResult data={data.url_analysis_result} />
                  ) : (
                    <URLResult data={{
                      scan_id: data.scan_id,
                      url: displayUrl || '',
                      risk_score: data.risk_score,
                      risk_level: data.risk_level,
                      urlscan: data.urlscan,
                      ip_info: data.ip_info,
                      domain_info: data.domain_info,
                      analyzed_at: data.analyzed_at || data.uploaded_at
                    }} />
                  )}
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
              </>
            )
          } else {
            // File Analysis Result
            return (
              <>
                <div>
                  <h1 className="text-2xl font-bold text-slate-50 mb-2">분석 결과</h1>
                  <p className="text-sm text-slate-200">
                    파일명: <span className="font-medium">{data.filename}</span>
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    업로드 시각: {new Date(data.uploaded_at).toLocaleString('ko-KR')}
                  </p>
                </div>

                {/* 탭 네비게이션: 일반 분석 / AI 심층 분석 분리 */}
                <div className="mt-6 border-b border-slate-800">
                  <div className="flex space-x-4">
                    <button
                      type="button"
                      onClick={() => setActiveTab('analysis')}
                      className={`px-4 py-2 text-sm font-semibold border-b-2 transition-colors ${
                        activeTab === 'analysis'
                          ? 'border-cyan-400 text-cyan-300'
                          : 'border-transparent text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      일반 분석 결과
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab('ai')}
                      className={`px-4 py-2 text-sm font-semibold border-b-2 transition-colors ${
                        activeTab === 'ai'
                          ? 'border-cyan-400 text-cyan-300'
                          : 'border-transparent text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      AI 심층 분석
                    </button>
                  </div>
                </div>

                <div className="mt-6">
                  {activeTab === 'analysis' ? (
                    <AnalysisResult data={data} />
                  ) : (
                    <AIInsight
                      scanId={data.scan_id}
                      riskScore={data.risk_score}
                      riskLevel={data.risk_level}
                      filename={data.filename}
                      aiAnalysis={aiAnalysis}
                      onAnalysisLoaded={setAiAnalysis}
                    />
                  )}
                </div>
              </>
            )
          }
        })()}
      </main>
    </div>
  )
}


