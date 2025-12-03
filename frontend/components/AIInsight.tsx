'use client'

import { useState, useEffect } from 'react'
import ReactMarkdown from 'react-markdown'

interface AIInsightProps {
  scanId: string
  riskScore: number
  riskLevel: string
  aiAnalysis: string | null
  onAnalysisLoaded: (analysis: string) => void
}

export default function AIInsight({ scanId, riskScore, riskLevel, aiAnalysis, onAnalysisLoaded }: AIInsightProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [locked, setLocked] = useState(true)
  const [userCredits, setUserCredits] = useState(0)

  useEffect(() => {
    const credits = parseInt(localStorage.getItem('credits') || '0')
    const role = localStorage.getItem('role')
    setUserCredits(credits)
    setLocked(role !== 'ADMIN' && credits === 0)
  }, [])

  const handleUnlock = async () => {
    setError('')
    setLoading(true)

    try {
      const token = localStorage.getItem('token')
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || ''
      const response = await fetch(`${apiUrl}/analysis/ai`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ scan_id: scanId }),
      })

      const data = await response.json()

      if (!response.ok) {
        if (response.status === 402) {
          setError(data.detail || '분석 티켓이 필요합니다.')
          return
        }
        throw new Error(data.detail || 'AI 분석을 불러오는 중 오류가 발생했습니다.')
      }

      onAnalysisLoaded(data.analysis)
      localStorage.setItem('credits', data.remaining_credits.toString())
      setUserCredits(data.remaining_credits)
      setLocked(false)
    } catch (err: any) {
      setError(err.message || 'AI 분석을 불러오는 중 오류가 발생했습니다.')
    } finally {
      setLoading(false)
    }
  }

  // Auto-load if already unlocked or if analysis exists
  useEffect(() => {
    if (aiAnalysis) {
      setLocked(false)
    }
  }, [aiAnalysis])

  if (locked && !aiAnalysis) {
    return (
      <div className="bg-slate-900/70 rounded-lg shadow-lg p-6 relative overflow-hidden border border-slate-700">
        <div className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center z-10">
          <div className="text-center bg-slate-900/90 p-8 rounded-xl shadow-2xl max-w-md border border-slate-700 text-slate-50">
            <div className="mb-2 text-xs font-semibold tracking-wide text-cyan-300 uppercase">
              AI 심층 분석
            </div>
            <h3 className="text-2xl font-bold mb-3">잠겨 있는 분석 결과</h3>
            <p className="text-slate-200 mb-6 text-sm leading-relaxed">
              보안 위협의 원인과 대응 방법을 한눈에 보고 싶다면 AI 심층 분석을 열어보세요.
            </p>
            <button
              onClick={handleUnlock}
              disabled={loading || userCredits === 0}
              className="px-6 py-3 bg-cyan-500 text-slate-900 font-semibold rounded-md hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'AI 분석을 준비하고 있습니다...' : `티켓 1개로 분석 보기`}
            </button>
            {error && (
              <p className="mt-4 text-sm text-red-300">
                {error || '잠금 해제 중 문제가 발생했습니다. 잠시 후 다시 시도해주세요.'}
              </p>
            )}
          </div>
        </div>
        <div className="opacity-30">
          <h2 className="text-2xl font-bold mb-6 text-slate-100">AI 심층 분석</h2>
          <div className="space-y-4">
            <div className="h-32 bg-slate-800/70 rounded"></div>
            <div className="h-32 bg-slate-800/70 rounded"></div>
            <div className="h-32 bg-slate-800/70 rounded"></div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="bg-slate-900/70 rounded-lg shadow-lg p-6 border border-slate-700">
      <h2 className="text-2xl font-bold mb-6 text-slate-50">AI 심층 분석</h2>

      {loading && !aiAnalysis ? (
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto mb-4"></div>
          <p className="text-slate-300">AI 분석 중...</p>
        </div>
      ) : aiAnalysis ? (
        <div className="prose max-w-none prose-invert">
          <ReactMarkdown
            components={{
              h2: ({ node, ...props }) => (
                <h2 className="text-xl font-bold mt-6 mb-3 text-slate-50" {...props} />
              ),
              h3: ({ node, ...props }) => (
                <h3 className="text-lg font-semibold mt-4 mb-2 text-slate-100" {...props} />
              ),
              p: ({ node, ...props }) => (
                <p className="mb-3 text-slate-100 leading-relaxed" {...props} />
              ),
              ul: ({ node, ...props }) => (
                <ul className="list-disc list-inside mb-3 space-y-1 text-slate-100" {...props} />
              ),
              li: ({ node, ...props }) => (
                <li className="text-slate-100" {...props} />
              ),
              code: ({ node, ...props }) => (
                <code className="bg-slate-800 px-1 py-0.5 rounded text-xs text-cyan-300" {...props} />
              ),
            }}
          >
            {aiAnalysis}
          </ReactMarkdown>
        </div>
      ) : (
        <div className="text-center py-12 text-slate-400">
          분석 결과가 없습니다.
        </div>
      )}
    </div>
  )
}

