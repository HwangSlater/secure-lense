'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

interface HistoryItem {
  scan_id: string
  filename: string
  risk_score: number
  risk_level: string
  uploaded_at: string
}

// Check if an item is a URL analysis
const isUrlAnalysis = (filename: string): boolean => {
  if (!filename) return false
  return filename.startsWith('http://') || filename.startsWith('https://')
}

interface CreditHistoryItem {
  purchased_at: string
  amount: number
  balance_after: number
}

export default function MyPage() {
  const router = useRouter()
  const [items, setItems] = useState<HistoryItem[]>([])
  const [creditHistory, setCreditHistory] = useState<CreditHistoryItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [deleting, setDeleting] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'files' | 'urls'>('files')

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) {
      router.push('/login')
      return
    }

    const fetchHistory = async () => {
      try {
        // 분석 이력
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || ''}/analysis/history`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        )

        let data
        try {
          data = await response.json()
        } catch (parseErr) {
          if (response.status >= 500) {
            setError('서버에서 문제가 발생했습니다. 잠시 후 다시 시도해주세요.')
            return
          } else if (response.status !== 404) {
            setError('분석 이력을 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
            return
          }
        }

        if (response.ok) {
          setItems(data?.analyses || [])
        } else if (response.status !== 404) {
          // 404는 "아직 이력이 없음"으로 간주
          const errorMessage = data?.detail || data?.message || '분석 이력을 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.'
          setError(errorMessage)
          return
        }

        // 결제 내역
        const creditsResponse = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || ''}/credits/history`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        )

        let creditsJson
        try {
          const creditsText = await creditsResponse.text()
          creditsJson = creditsText ? JSON.parse(creditsText) : []
        } catch (parseErr) {
          creditsJson = []
        }

        if (creditsResponse.ok) {
          setCreditHistory(creditsJson || [])
        } else if (creditsResponse.status !== 404) {
          const errorMessage = creditsJson?.detail || creditsJson?.message || '결제 내역을 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.'
          setError(errorMessage)
          return
        }
      } catch (err: any) {
        // Show user-friendly error message
        let errorMessage = '마이페이지 정보를 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.'
        
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

    fetchHistory()
  }, [router])

  const handleDelete = async (scanId: string) => {
    if (!confirm('정말 이 분석 결과를 삭제하시겠습니까?')) {
      return
    }

    setDeleting(scanId)
    try {
      const token = localStorage.getItem('token')
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || ''}/analysis/${scanId}`,
        {
          method: 'DELETE',
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      )

      if (!response.ok) {
        let errorMessage = '분석 결과 삭제에 실패했습니다. 잠시 후 다시 시도해주세요.'
        try {
          const data = await response.json()
          errorMessage = data.detail || data.message || errorMessage
        } catch {
          // If response is not JSON, use default message
        }
        throw new Error(errorMessage)
      }

      // 목록에서 제거
      setItems(items.filter((item) => item.scan_id !== scanId))
    } catch (err: any) {
      // Show user-friendly error message
      let errorMessage = '분석 결과 삭제 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.'
      
      if (err.message && !err.message.includes('<!DOCTYPE') && !err.message.includes('Error:')) {
        errorMessage = err.message
      } else if (err.name === 'TypeError' && err.message.includes('fetch')) {
        errorMessage = '서버에 연결할 수 없습니다. 네트워크 연결을 확인해주세요.'
      }
      
      setError(errorMessage)
    } finally {
      setDeleting(null)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-slate-100">분석 이력을 불러오는 중입니다...</p>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-transparent">
      <header className="bg-slate-900/70 border-b border-slate-800 backdrop-blur-sm">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between text-slate-100">
          <Link href="/" className="text-xl font-extrabold logo-gradient">
            SecureLens
          </Link>
          <Link href="/dashboard" className="text-sm text-slate-200 hover:text-white">
            대시보드로 돌아가기
          </Link>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-50 mb-2">마이페이지</h1>
          <p className="text-sm text-slate-200">
            최근 분석 이력과 분석 티켓 결제 내역을 한눈에 확인할 수 있습니다.
          </p>
        </div>

        {error && (
          <div className="mb-4 bg-red-900/40 border border-red-500/70 text-red-100 px-4 py-3 rounded">
            {error}
          </div>
        )}

        {/* 분석 이력 */}
        <section>
          <div className="flex items-center justify-between mb-3 border-b border-slate-700 pb-2">
            <h2 className="text-lg font-semibold text-slate-50">분석 이력</h2>
            <div className="flex space-x-2">
              <button
                onClick={() => setActiveTab('files')}
                className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                  activeTab === 'files'
                    ? 'bg-cyan-500 text-slate-900'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                파일 분석
              </button>
              <button
                onClick={() => setActiveTab('urls')}
                className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
                  activeTab === 'urls'
                    ? 'bg-cyan-500 text-slate-900'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                URL 분석
              </button>
            </div>
          </div>

          {(() => {
            const filteredItems = items.filter(item => 
              activeTab === 'files' ? !isUrlAnalysis(item.filename) : isUrlAnalysis(item.filename)
            )

            if (filteredItems.length === 0) {
              return (
                <div className="bg-slate-900/70 rounded-lg shadow p-6 text-center text-slate-300 border border-slate-700">
                  {activeTab === 'files'
                    ? '아직 파일 분석 이력이 없습니다. 대시보드에서 파일을 업로드해 분석을 시작해보세요.'
                    : '아직 URL 분석 이력이 없습니다. 대시보드에서 URL을 분석해보세요.'}
                </div>
              )
            }

            return (
              <div className="bg-slate-900/70 rounded-lg shadow overflow-hidden border border-slate-700">
                <table className="min-w-full divide-y divide-slate-700">
                  <thead className="bg-slate-800/50">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                        {activeTab === 'files' ? '파일명' : 'URL'}
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                        위험도
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                        {activeTab === 'files' ? '업로드 시각' : '분석 시각'}
                      </th>
                      <th className="px-4 py-3"></th>
                    </tr>
                  </thead>
                  <tbody className="bg-slate-900/70 divide-y divide-slate-700">
                    {filteredItems.map((item) => {
                      // 파일명이 길면 앞부분만 표시하고 확장자는 유지
                      const getDisplayName = (name: string, maxLength: number = 30) => {
                        if (name.length <= maxLength) {
                          return name
                        }
                        if (activeTab === 'urls') {
                          // URL의 경우 앞부분과 끝부분을 보여줌
                          return name.substring(0, maxLength - 7) + '....' + name.substring(name.length - 3)
                        }
                        // 파일명의 경우 확장자 유지
                        const lastDotIndex = name.lastIndexOf('.')
                        if (lastDotIndex === -1) {
                          return name.substring(0, maxLength - 4) + '....'
                        }
                        const nameWithoutExt = name.substring(0, lastDotIndex)
                        const extension = name.substring(lastDotIndex)
                        const maxNameLength = maxLength - extension.length - 4
                        if (nameWithoutExt.length <= maxNameLength) {
                          return name
                        }
                        return nameWithoutExt.substring(0, maxNameLength) + '....' + extension
                      }

                      return (
                        <tr key={item.scan_id} className="hover:bg-slate-800/50">
                          <td className="px-4 py-3 text-sm text-cyan-400">
                            <Link href={`/result/${item.scan_id}`} className="hover:underline break-all" title={item.filename}>
                              {getDisplayName(item.filename)}
                            </Link>
                          </td>
                          <td className="px-4 py-3 text-sm text-slate-200">
                            {item.risk_score}/100 · {item.risk_level}
                          </td>
                          <td className="px-4 py-3 text-sm text-slate-400">
                            {new Date(item.uploaded_at).toLocaleString('ko-KR')}
                          </td>
                          <td className="px-4 py-3 text-right text-sm">
                            <div className="flex items-center justify-end space-x-2">
                              <Link
                                href={`/result/${item.scan_id}`}
                                className="inline-flex items-center px-3 py-1.5 border border-slate-600 rounded-md text-slate-200 hover:bg-slate-800/80"
                              >
                                상세 보기
                              </Link>
                              <button
                                onClick={() => handleDelete(item.scan_id)}
                                disabled={deleting === item.scan_id}
                                className="inline-flex items-center px-3 py-1.5 border border-red-600 rounded-md text-red-300 hover:bg-red-900/30 disabled:opacity-50 disabled:cursor-not-allowed"
                              >
                                {deleting === item.scan_id ? '삭제 중...' : '삭제'}
                              </button>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )
          })()}
        </section>

        {/* 결제 내역 */}
        <section>
          <h2 className="text-lg font-semibold text-slate-50 mb-3 border-b border-slate-700 pb-2">
            분석 티켓 결제 내역
          </h2>
          {creditHistory.length === 0 ? (
            <div className="bg-slate-900/70 rounded-lg shadow p-6 text-center text-slate-300 border border-slate-700">
              아직 결제 내역이 없습니다. 상단 메뉴의 티켓 구매 또는 대시보드에서 티켓을 충전해보세요.
            </div>
          ) : (
            <div className="bg-slate-900/70 rounded-lg shadow overflow-hidden border border-slate-700">
              <table className="min-w-full divide-y divide-slate-700">
                <thead className="bg-slate-800/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                      결제 시각
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                      충전 티켓 수
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                      충전 후 보유 티켓
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-slate-900/70 divide-y divide-slate-700">
                  {creditHistory.map((item, index) => (
                    <tr key={`${item.purchased_at}-${index}`} className="hover:bg-slate-800/50">
                      <td className="px-4 py-3 text-sm text-slate-200">
                        {new Date(item.purchased_at).toLocaleString('ko-KR')}
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-200">{item.amount}개</td>
                      <td className="px-4 py-3 text-sm text-slate-200">{item.balance_after}개</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  )
}


