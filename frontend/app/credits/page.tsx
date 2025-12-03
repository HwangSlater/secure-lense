'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

interface Plan {
  id: string
  amount: number
  label: string
  description: string
  price: number
}

export default function CreditsPage() {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const plans: Plan[] = [
    {
      id: 'starter',
      amount: 5,
      label: '시작 패키지',
      description: '테스트용 소량 분석에 적합합니다.',
      price: 2000,
    },
    {
      id: 'standard',
      amount: 10,
      label: '표준 패키지',
      description: '일상적인 악성코드/피싱 분석에 권장합니다.',
      price: 3500,
    },
    {
      id: 'pro',
      amount: 30,
      label: '프로 패키지',
      description: '보안팀/동아리 등 다수 사용자가 함께 사용할 때 적합합니다.',
      price: 9000,
    },
  ]

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) {
      router.push('/login')
    }
  }, [router])

  const handlePurchase = async (plan: Plan) => {
    setError('')
    setSuccess('')
    setLoading(true)

    try {
      const token = localStorage.getItem('token')
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/credits/charge`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ amount: plan.amount }),
        }
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || '티켓 충전에 실패했습니다.')
      }

      if (typeof data.new_balance === 'number') {
        localStorage.setItem('credits', data.new_balance.toString())
      }

      setSuccess(`${plan.amount}개의 분석 티켓이 가상 결제로 충전되었습니다.`)
    } catch (err: any) {
      setError(err.message || '티켓 충전에 실패했습니다.')
    } finally {
      setLoading(false)
    }
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

      <main className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-50 mb-2">분석 티켓 구매 (가상)</h1>
          <p className="text-sm text-slate-200">
            AI 심층 분석은 분석 1회당 티켓 1개를 사용합니다. 여기서의 결제는 연습용 가상 결제로, 실제 요금이 청구되지는
            않습니다.
          </p>
        </div>

        {error && (
          <div className="bg-red-900/40 border border-red-500/70 text-red-100 px-4 py-3 rounded">
            {error}
          </div>
        )}

        {success && (
          <div className="bg-emerald-900/40 border border-emerald-500/70 text-emerald-100 px-4 py-3 rounded">
            {success}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {plans.map((plan) => (
            <div
              key={plan.id}
              className="bg-slate-900/70 rounded-lg shadow-lg p-6 flex flex-col justify-between border border-slate-700"
            >
              <div>
                <h2 className="text-lg font-bold text-slate-50 mb-1">{plan.label}</h2>
                <p className="text-sm text-slate-300 mb-3">{plan.description}</p>
                <p className="text-2xl font-bold text-slate-50 mb-1">
                  {plan.price.toLocaleString('ko-KR')}원
                </p>
                <p className="text-xs text-slate-400">
                  분석 티켓 {plan.amount}개 · AI 심층 분석 {plan.amount}회 사용 가능
                </p>
              </div>
              <button
                onClick={() => handlePurchase(plan)}
                disabled={loading}
                className="mt-4 w-full bg-cyan-500 text-slate-900 font-semibold py-2 px-4 rounded-md hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? '구매 처리 중...' : '구매하기'}
              </button>
            </div>
          ))}
        </div>

        <p className="text-xs text-slate-500">
          실제 Gemini API 요금은 Google Cloud의 과금 정책에 따라 달라지며, 이 페이지의 가격은 연습용 예시일 뿐입니다.
        </p>
      </main>
    </div>
  )
}


