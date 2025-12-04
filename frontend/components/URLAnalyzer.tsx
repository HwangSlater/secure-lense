'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'

interface URLAnalyzerProps {
  onAnalysisComplete?: (data: any) => void
}

export default function URLAnalyzer({ onAnalysisComplete }: URLAnalyzerProps) {
  const router = useRouter()
  const [url, setUrl] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState('')

  const handleAnalyze = async () => {
    if (!url.trim()) {
      setError('URL을 입력해주세요.')
      return
    }

    setError('')
    setAnalyzing(true)

    try {
      const token = localStorage.getItem('token')
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || ''
      
      const response = await fetch(`${apiUrl}/url/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ url: url.trim() }),
      })

      // Check if response is JSON
      const contentType = response.headers.get('content-type')
      if (!contentType || !contentType.includes('application/json')) {
        const text = await response.text()
        throw new Error(`서버 응답 오류: ${text || '알 수 없는 오류'}`)
      }

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || data.message || 'URL 분석에 실패했습니다.')
      }

      // Navigate to result page
      router.push(`/result/${data.scan_id}`)
      
      if (onAnalysisComplete) {
        onAnalysisComplete(data)
      }
    } catch (err: any) {
      setError(err.message || 'URL 분석 중 오류가 발생했습니다.')
    } finally {
      setAnalyzing(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !analyzing) {
      handleAnalyze()
    }
  }

  return (
    <div className="bg-slate-900/70 rounded-lg shadow-lg p-6 border border-slate-700">
      <div className="mb-4">
        <h2 className="text-2xl font-bold text-slate-50 mb-2">URL 분석</h2>
        <p className="text-sm text-slate-300 mb-4">
          의심스러운 링크나 URL을 입력하여 위협 여부를 확인하세요. 이메일에 포함된 링크도 분석할 수 있습니다.
        </p>
        <div className="mb-4 p-3 bg-slate-800/50 rounded-lg border border-slate-700">
          <p className="text-xs text-slate-300">
            <span className="font-semibold text-cyan-300">참고:</span> 이메일 파일(.eml)인 경우, 제목과 내용을 입력하면 분석 정확도가 향상됩니다.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        <div>
          <label htmlFor="url-input" className="block text-sm font-medium text-slate-200 mb-2">
            분석할 URL
          </label>
          <input
            id="url-input"
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="https://example.com 또는 example.com"
            className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-md text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
            disabled={analyzing}
          />
          <p className="mt-1 text-xs text-slate-400">
            http:// 또는 https://를 생략해도 자동으로 추가됩니다.
          </p>
        </div>

        {error && (
          <div className="bg-red-900/40 border border-red-500/70 text-red-100 px-4 py-3 rounded text-sm">
            {error}
          </div>
        )}

        <button
          onClick={handleAnalyze}
          disabled={analyzing || !url.trim()}
          className="w-full px-6 py-3 bg-cyan-500 text-slate-900 font-semibold rounded-md hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {analyzing ? (
            <span className="flex items-center justify-center">
              <svg
                className="animate-spin -ml-1 mr-3 h-5 w-5 text-slate-900"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                ></circle>
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                ></path>
              </svg>
              URL 분석 중...
            </span>
          ) : (
            'URL 분석 시작'
          )}
        </button>

        <div className="mt-4 p-4 bg-slate-800/50 rounded border border-slate-700">
          <p className="text-xs text-slate-400">
            <strong className="text-slate-300">URL 분석 기능:</strong>
          </p>
          <ul className="mt-2 space-y-1 text-xs text-slate-400 list-disc list-inside">
            <li>URLScan.io를 통한 실시간 URL 스캔</li>
            <li>도메인 및 IP 주소 정보 확인</li>
            <li>악성 URL 탐지 및 위협 점수 계산</li>
            <li>스크린샷 및 상세 분석 결과 제공</li>
          </ul>
        </div>
      </div>
    </div>
  )
}

