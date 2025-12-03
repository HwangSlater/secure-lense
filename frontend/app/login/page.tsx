'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const formData = new FormData()
      formData.append('username', username)
      formData.append('password', password)

      const apiUrl = process.env.NEXT_PUBLIC_API_URL || ''
      const response = await fetch(`${apiUrl}/auth/login`, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
        },
        body: formData,
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || '로그인에 실패했습니다.')
      }

      // Store token and user info
      localStorage.setItem('token', data.access_token)
      localStorage.setItem('username', data.username)
      localStorage.setItem('role', data.role)
      localStorage.setItem('credits', data.credits.toString())

      // Redirect to dashboard
      router.push('/dashboard')
    } catch (err: any) {
      setError(err.message || '로그인 중 오류가 발생했습니다.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="bg-slate-900/80 border border-slate-700 backdrop-blur-xl p-8 rounded-2xl shadow-2xl w-full max-w-md">
        <h1 className="text-3xl font-bold text-center mb-8">
          <Link href="/" className="logo-gradient text-4xl font-extrabold block mb-2">
            SecureLens
          </Link>
          <span className="text-slate-200 text-base">보안 분석 콘솔 로그인</span>
        </h1>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="username" className="block text-sm font-medium text-slate-200 mb-2">
              아이디
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="사용자 아이디 입력"
              required
              className="w-full px-4 py-2 border border-slate-600 bg-slate-900/60 text-slate-100 rounded-md focus:outline-none focus:ring-2 focus:ring-cyan-500 placeholder:text-slate-500"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-slate-200 mb-2">
              비밀번호
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="비밀번호 입력"
              required
              className="w-full px-4 py-2 border border-slate-600 bg-slate-900/60 text-slate-100 rounded-md focus:outline-none focus:ring-2 focus:ring-cyan-500 placeholder:text-slate-500"
            />
          </div>

          {error && (
            <div className="bg-red-900/40 border border-red-500/70 text-red-100 px-4 py-3 rounded-md text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-cyan-500 text-slate-900 font-semibold py-2 px-4 rounded-md hover:bg-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? '로그인 중...' : '로그인'}
          </button>
        </form>

        <div className="mt-8 p-4 bg-slate-900/70 border border-slate-700 rounded-md">
          <p className="text-sm font-semibold text-slate-100 mb-2">테스트 계정 안내</p>
          <div className="text-sm text-slate-300 space-y-1">
            <p>일반 사용자: user / user123 (티켓 0개)</p>
            <p>관리자: admin / admin123 (무제한)</p>
          </div>
        </div>
      </div>
    </div>
  )
}

