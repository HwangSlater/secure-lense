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
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/analysis/ai`, {
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
      <div className="bg-white rounded-lg shadow-lg p-6 relative overflow-hidden">
        <div className="absolute inset-0 bg-gray-900 bg-opacity-50 backdrop-blur-sm flex items-center justify-center z-10">
          <div className="text-center bg-white p-8 rounded-lg shadow-xl max-w-md">
            <div className="text-6xl mb-4">🔒</div>
            <h3 className="text-2xl font-bold text-gray-800 mb-4">AI 심층 분석 잠금</h3>
            <p className="text-gray-600 mb-6">
              보안 전문가의 상세 분석 및 대응 방법을 확인하세요
            </p>
            <button
              onClick={handleUnlock}
              disabled={loading || userCredits === 0}
              className="px-6 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? '로딩 중...' : `티켓 1개로 잠금 해제`}
            </button>
            {error && (
              <p className="mt-4 text-sm text-red-600">{error}</p>
            )}
          </div>
        </div>
        <div className="opacity-30">
          <h2 className="text-2xl font-bold mb-6 text-gray-800">AI 심층 분석</h2>
          <div className="space-y-4">
            <div className="h-32 bg-gray-200 rounded"></div>
            <div className="h-32 bg-gray-200 rounded"></div>
            <div className="h-32 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <h2 className="text-2xl font-bold mb-6 text-gray-800">AI 심층 분석</h2>

      {loading && !aiAnalysis ? (
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">AI 분석 중...</p>
        </div>
      ) : aiAnalysis ? (
        <div className="prose max-w-none">
          <ReactMarkdown
            components={{
              h2: ({ node, ...props }) => (
                <h2 className="text-xl font-bold mt-6 mb-3 text-gray-800" {...props} />
              ),
              h3: ({ node, ...props }) => (
                <h3 className="text-lg font-semibold mt-4 mb-2 text-gray-700" {...props} />
              ),
              p: ({ node, ...props }) => (
                <p className="mb-3 text-gray-700 leading-relaxed" {...props} />
              ),
              ul: ({ node, ...props }) => (
                <ul className="list-disc list-inside mb-3 space-y-1 text-gray-700" {...props} />
              ),
              li: ({ node, ...props }) => (
                <li className="text-gray-700" {...props} />
              ),
              code: ({ node, ...props }) => (
                <code className="bg-gray-100 px-1 py-0.5 rounded text-sm" {...props} />
              ),
            }}
          >
            {aiAnalysis}
          </ReactMarkdown>
        </div>
      ) : (
        <div className="text-center py-12 text-gray-500">
          분석 결과가 없습니다.
        </div>
      )}
    </div>
  )
}

