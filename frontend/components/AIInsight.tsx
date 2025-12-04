'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import ReactMarkdown from 'react-markdown'

interface AIInsightProps {
  scanId: string
  riskScore: number
  riskLevel: string
  filename: string
  aiAnalysis: string | null
  onAnalysisLoaded: (analysis: string) => void
}

export default function AIInsight({ scanId, riskScore, riskLevel, filename, aiAnalysis, onAnalysisLoaded }: AIInsightProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [locked, setLocked] = useState(true)
  const [userCredits, setUserCredits] = useState(0)
  const [showEmailInputs, setShowEmailInputs] = useState(false)
  const [emailSubject, setEmailSubject] = useState('')
  const [emailContent, setEmailContent] = useState('')

  useEffect(() => {
    const credits = parseInt(localStorage.getItem('credits') || '0')
    const role = localStorage.getItem('role')
    setUserCredits(credits)
    setLocked(role !== 'ADMIN' && credits === 0)
    
    // Load saved email info from localStorage if available
    const savedEmailInfo = localStorage.getItem(`email_info_${scanId}`)
    if (savedEmailInfo) {
      try {
        const emailInfo = JSON.parse(savedEmailInfo)
        setEmailSubject(emailInfo.subject || '')
        setEmailContent(emailInfo.content || '')
        if (emailInfo.subject || emailInfo.content) {
          setShowEmailInputs(true)
        }
      } catch (e) {
        // Ignore parse errors
      }
    }
  }, [scanId])

  const handleUnlock = async () => {
    setError('')
    setLoading(true)

    try {
      const token = localStorage.getItem('token')
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || ''
      const requestBody: any = { scan_id: scanId }
      if (emailSubject.trim()) {
        requestBody.email_subject = emailSubject.trim()
      }
      if (emailContent.trim()) {
        requestBody.email_content = emailContent.trim()
      }
      
      const response = await fetch(`${apiUrl}/analysis/ai`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(requestBody),
      })

      // Check if response is JSON
      let data
      try {
        data = await response.json()
      } catch (parseErr) {
        if (response.status === 404) {
          setError('AI 분석 서비스를 찾을 수 없습니다. 잠시 후 다시 시도해주세요.')
          return
        } else if (response.status >= 500) {
          setError('서버에서 문제가 발생했습니다. 잠시 후 다시 시도해주세요.')
          return
        } else {
          setError('AI 분석을 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
          return
        }
      }

      if (!response.ok) {
        if (response.status === 402) {
          setError(data.detail || '분석 티켓이 필요합니다.')
          return
        }
        // Use user-friendly error message from backend
        const errorMessage = data.detail || data.message || 'AI 분석을 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.'
        setError(errorMessage)
        return
      }

      onAnalysisLoaded(data.analysis)
      localStorage.setItem('credits', data.remaining_credits.toString())
      setUserCredits(data.remaining_credits)
      setLocked(false)
    } catch (err: any) {
      // Show user-friendly error message
      let errorMessage = 'AI 분석을 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.'
      
      if (err.message && !err.message.includes('<!DOCTYPE') && !err.message.includes('Error:')) {
        // Use the error message if it's already user-friendly
        errorMessage = err.message
      } else if (err.name === 'TypeError' && err.message.includes('fetch')) {
        errorMessage = '서버에 연결할 수 없습니다. 네트워크 연결을 확인해주세요.'
      }
      
      setError(errorMessage)
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
            <h3 className="text-2xl font-bold mb-3">AI 심층 분석 잠금 해제</h3>
            <p className="text-slate-200 mb-4 text-sm leading-relaxed">
              티켓을 구매하면 더 상세한 AI 분석 결과를 확인할 수 있습니다.
            </p>
            <div className="bg-slate-800/50 rounded-lg p-4 mb-6 border border-slate-700">
              <p className="text-xs text-slate-300 mb-2">
                <span className="font-semibold text-cyan-300">AI 심층 분석</span>에서는 다음 정보를 제공합니다:
              </p>
              <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
                <li>악성코드의 상세 동작 원리 분석</li>
                <li>피싱 이메일의 위조 기법 및 대응 방법</li>
                <li>구체적인 보안 권장사항 및 제거 방법</li>
                <li>유사한 위협 사례 및 참고 자료</li>
              </ul>
            </div>
            {userCredits === 0 ? (
              <div className="space-y-3">
                <p className="text-sm text-slate-300 mb-4">
                  현재 보유 티켓: <span className="font-semibold text-red-300">0개</span>
                </p>
                <Link
                  href="/credits"
                  className="block w-full px-6 py-3 bg-cyan-500 text-slate-900 font-semibold rounded-md hover:bg-cyan-400 text-center transition-colors"
                >
                  티켓 구매하러 가기 →
                </Link>
                <p className="text-xs text-slate-400 text-center">
                  시작 패키지: 5개 티켓 2,000원부터
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                <p className="text-sm text-slate-300">
                  보유 티켓: <span className="font-semibold text-cyan-300">{userCredits}개</span>
                </p>

                {/* 이메일 정보 입력 (선택사항) */}
                <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                  <div className="flex items-start space-x-2 mb-3">
                    <input
                      id="email-info-check-locked"
                      type="checkbox"
                      className="mt-1 h-4 w-4 text-cyan-500 border-slate-500 rounded bg-slate-900"
                      checked={showEmailInputs}
                      onChange={(e) => setShowEmailInputs(e.target.checked)}
                    />
                    <label htmlFor="email-info-check-locked" className="text-sm font-medium text-slate-100">
                      이메일 정보 추가 (선택사항)
                    </label>
                  </div>
                  
                  {showEmailInputs && (
                    <div className="mt-3 space-y-3">
                      <div>
                        <label htmlFor="email-subject-locked" className="block text-xs text-slate-300 mb-1">
                          이메일 제목
                        </label>
                        <input
                          id="email-subject-locked"
                          type="text"
                          value={emailSubject}
                          onChange={(e) => setEmailSubject(e.target.value)}
                          placeholder="예: 긴급 보안 업데이트 안내"
                          className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                        />
                      </div>
                      <div>
                        <label htmlFor="email-content-locked" className="block text-xs text-slate-300 mb-1">
                          이메일 내용
                        </label>
                        <textarea
                          id="email-content-locked"
                          value={emailContent}
                          onChange={(e) => setEmailContent(e.target.value)}
                          placeholder="이메일 본문 내용을 입력하세요..."
                          rows={3}
                          className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 resize-none"
                        />
                      </div>
                    </div>
                  )}
                </div>

                <button
                  onClick={handleUnlock}
                  disabled={loading}
                  className="w-full px-6 py-3 bg-cyan-500 text-slate-900 font-semibold rounded-md hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {loading ? 'AI 분석을 준비하고 있습니다...' : `티켓 1개로 분석 보기`}
                </button>
                {error && (
                  <p className="mt-2 text-sm text-red-300 text-center">
                    {error}
                  </p>
                )}
              </div>
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
          <div className="flex flex-col items-center">
            <div className="relative w-16 h-16 mb-6">
              <div className="absolute inset-0 border-4 border-cyan-400/30 rounded-full"></div>
              <div className="absolute inset-0 border-4 border-transparent border-t-cyan-400 rounded-full animate-spin"></div>
            </div>
            <p className="text-slate-300 text-lg font-semibold mb-2">AI 분석 중...</p>
            <p className="text-slate-400 text-sm">분석에 몇 분 정도 걸릴 수 있습니다.</p>
            <div className="mt-4 flex space-x-2">
              <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
              <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
              <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
            </div>
          </div>
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
            {(() => {
              // 긴 인사말이 첫 문단에 있는 경우 제거
              let processedAnalysis = aiAnalysis
              // "안녕하세요"로 시작하고 "경력"과 "전문가"가 포함된 첫 문단 제거
              const greetingPattern = /^[^\n]*(?:안녕하세요[^\n]*(?:경력|전문가)[^\n]*의뢰하신[^\n]*파일에 대한[^\n]*분석 결과[^\n]*(?:일반인도[^\n]*이해하기[^\n]*쉽게[^\n]*설명[^\n]*드리겠습니다)?)[^\n]*\n?/i
              processedAnalysis = processedAnalysis.replace(greetingPattern, '')
              // 파일명만 포함된 간단한 문구로 시작
              return `${filename} 파일에 대한 분석 결과\n\n${processedAnalysis.trim()}`
            })()}
          </ReactMarkdown>
        </div>
      ) : (
        <div className="text-center py-12">
          <div className="bg-slate-800/50 rounded-lg p-6 border border-slate-700 max-w-md mx-auto">
            <p className="text-slate-300 mb-4">
              아직 AI 심층 분석 결과가 없습니다.
            </p>
            <p className="text-sm text-slate-400 mb-6">
              티켓을 구매하면 더 상세한 분석 결과를 확인할 수 있습니다.
            </p>
            {userCredits === 0 ? (
              <Link
                href="/credits"
                className="inline-block px-6 py-3 bg-cyan-500 text-slate-900 font-semibold rounded-md hover:bg-cyan-400 transition-colors"
              >
                티켓 구매하러 가기 →
              </Link>
            ) : (
              <div className="space-y-3">
                {/* 이메일 정보 입력 (선택사항) */}
                <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                  <div className="flex items-start space-x-2 mb-3">
                    <input
                      id="email-info-check-unlocked"
                      type="checkbox"
                      className="mt-1 h-4 w-4 text-cyan-500 border-slate-500 rounded bg-slate-900"
                      checked={showEmailInputs}
                      onChange={(e) => setShowEmailInputs(e.target.checked)}
                    />
                    <label htmlFor="email-info-check-unlocked" className="text-sm font-medium text-slate-100">
                      이메일 정보 추가 (선택사항)
                    </label>
                  </div>
                  
                  {showEmailInputs && (
                    <div className="mt-3 space-y-3">
                      <div>
                        <label htmlFor="email-subject-unlocked" className="block text-xs text-slate-300 mb-1">
                          이메일 제목
                        </label>
                        <input
                          id="email-subject-unlocked"
                          type="text"
                          value={emailSubject}
                          onChange={(e) => setEmailSubject(e.target.value)}
                          placeholder="예: 긴급 보안 업데이트 안내"
                          className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                        />
                      </div>
                      <div>
                        <label htmlFor="email-content-unlocked" className="block text-xs text-slate-300 mb-1">
                          이메일 내용
                        </label>
                        <textarea
                          id="email-content-unlocked"
                          value={emailContent}
                          onChange={(e) => setEmailContent(e.target.value)}
                          placeholder="이메일 본문 내용을 입력하세요..."
                          rows={3}
                          className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 resize-none"
                        />
                      </div>
                    </div>
                  )}
                </div>

                <button
                  onClick={handleUnlock}
                  disabled={loading}
                  className="w-full px-6 py-3 bg-cyan-500 text-slate-900 font-semibold rounded-md hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {loading ? 'AI 분석 중...' : `티켓 1개로 분석 시작하기`}
                </button>
                {error && (
                  <p className="mt-2 text-sm text-red-300 text-center">
                    {error}
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

