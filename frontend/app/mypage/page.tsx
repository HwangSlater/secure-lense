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

        const data = await response.json()

        if (response.ok) {
          setItems(data.analyses || [])
        } else if (response.status !== 404) {
          // 404는 "아직 이력이 없음"으로 간주
          throw new Error(data.detail || '분석 이력을 불러오는 중 오류가 발생했습니다.')
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

        const creditsText = await creditsResponse.text()
        const creditsJson = creditsText ? JSON.parse(creditsText) : []

        if (creditsResponse.ok) {
          setCreditHistory(creditsJson || [])
        } else if (creditsResponse.status !== 404) {
          throw new Error(creditsJson.detail || '결제 내역을 불러오는 중 오류가 발생했습니다.')
        }
      } catch (err: any) {
        setError(err.message || '마이페이지 정보를 불러오는 중 오류가 발생했습니다.')
      } finally {
        setLoading(false)
      }
    }

    fetchHistory()
  }, [router])

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
          <h2 className="text-lg font-semibold text-slate-50 mb-3 border-b border-slate-700 pb-2">
            분석 이력
          </h2>
          {items.length === 0 ? (
            <div className="bg-slate-900/70 rounded-lg shadow p-6 text-center text-slate-300 border border-slate-700">
              아직 분석 이력이 없습니다. 대시보드에서 파일을 업로드해 분석을 시작해보세요.
            </div>
          ) : (
            <div className="bg-slate-900/70 rounded-lg shadow overflow-hidden border border-slate-700">
              <table className="min-w-full divide-y divide-slate-700">
                <thead className="bg-slate-800/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                      파일명
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                      위험도
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                      업로드 시각
                    </th>
                    <th className="px-4 py-3"></th>
                  </tr>
                </thead>
                <tbody className="bg-slate-900/70 divide-y divide-slate-700">
                  {items.map((item) => (
                    <tr key={item.scan_id} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3 text-sm text-cyan-400">
                      <Link href={`/result/${item.scan_id}`} className="hover:underline">
                          {item.filename}
                        </Link>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-200">
                        {item.risk_score}/100 · {item.risk_level}
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-400">
                        {new Date(item.uploaded_at).toLocaleString('ko-KR')}
                      </td>
                      <td className="px-4 py-3 text-right text-sm">
                      <Link
                        href={`/result/${item.scan_id}`}
                          className="inline-flex items-center px-3 py-1.5 border border-slate-600 rounded-md text-slate-200 hover:bg-slate-800/80"
                        >
                          상세 보기
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
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


