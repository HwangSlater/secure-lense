'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import FileUpload from '@/components/FileUpload'
import AnalysisResult from '@/components/AnalysisResult'
import AIInsight from '@/components/AIInsight'

interface UserInfo {
  username: string
  role: string
  credits: number
}

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
  file_deleted_at: string
}

export default function DashboardPage() {
  const router = useRouter()
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [analysisData, setAnalysisData] = useState<AnalysisData | null>(null)
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) {
      router.push('/login')
      return
    }

    fetchUserInfo()
  }, [])

  const fetchUserInfo = async () => {
    try {
      const token = localStorage.getItem('token')
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || ''
      const response = await fetch(`${apiUrl}/auth/me`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      if (!response.ok) {
        throw new Error('인증 실패')
      }

      const data = await response.json()
      setUserInfo(data)
      localStorage.setItem('username', data.username)
      localStorage.setItem('role', data.role)
      localStorage.setItem('credits', data.credits.toString())
    } catch (err) {
      localStorage.removeItem('token')
      router.push('/login')
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = () => {
    localStorage.clear()
    router.push('/login')
  }

  const handleAnalysisComplete = (data: AnalysisData) => {
    // 업로드가 성공하면 결과 페이지로 이동
    router.push(`/result/${data.scan_id}`)
  }

  const handleAiAutoLoaded = (analysis: string) => {
    setAiAnalysis(analysis)
  }

  const handleCreditsUpdated = () => {
    fetchUserInfo()
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-xl text-slate-100">로딩 중...</div>
      </div>
    )
  }

  if (!userInfo) {
    return null
  }

  return (
    <div className="min-h-screen bg-transparent">
      {/* Header */}
      <header className="bg-slate-900/70 border-b border-slate-800 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 text-slate-100">
          <div className="flex justify-between items-center">
            <div>
              <div className="flex items-baseline space-x-2">
                <Link
                  href="/"
                  className="text-2xl font-extrabold logo-gradient hover:opacity-90 transition-opacity"
                >
                  SecureLens
                </Link>
                <span className="text-sm text-slate-300">
                  지능형 악성코드 및 스피어피싱 분석
                </span>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-sm text-slate-200">
                접속자: <span className="font-semibold">{userInfo.username}</span>
                {userInfo.role !== 'ADMIN' && (
                  <> | 보유 티켓: <span className="font-semibold">{userInfo.credits}</span>개</>
                )}
              </div>
              <Link
                href="/mypage"
                className="px-3 py-2 text-sm border border-slate-500 rounded-md text-slate-100 hover:bg-slate-800/80"
              >
                마이페이지
              </Link>
              <Link
                href="/credits"
                className="px-3 py-2 text-sm border border-cyan-400 text-cyan-300 rounded-md hover:bg-cyan-500/10"
              >
                티켓 구매
              </Link>
              <button
                onClick={handleLogout}
                className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700"
              >
                로그아웃
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* File Upload Section */}
        <div className="mb-8">
          <FileUpload
            onAnalysisComplete={handleAnalysisComplete}
            onAiAnalysisLoaded={handleAiAutoLoaded}
          />
        </div>

        {/* Help Section */}
        <div className="mt-4 bg-slate-900/60 rounded-lg shadow-lg p-6 border border-slate-700">
          <h2 className="text-xl font-bold mb-4 text-slate-50">자주 묻는 질문</h2>
          <div className="space-y-4 text-slate-200">
            <div>
              <p className="font-semibold">어떤 파일을 분석할 수 있나요?</p>
              <p className="text-sm text-slate-300">- 이메일 첨부파일 (.exe, .dll, .pdf, .docx)</p>
              <p className="text-sm text-slate-300">- 의심스러운 이메일 (.eml)</p>
            </div>
            <div>
              <p className="font-semibold">위험도는 어떻게 계산되나요?</p>
              <p className="text-sm text-slate-300">
                - 여러 보안 엔진의 결과를 종합하여 0-100점으로 계산됩니다
              </p>
            </div>
            <div>
              <p className="font-semibold">AI 분석이 필요한가요?</p>
              <p className="text-sm text-slate-300">- 기본 분석으로도 위험 여부를 확인할 수 있지만,</p>
              <p className="text-sm text-slate-300">
                - AI 분석은 &apos;왜 위험한지&apos;와 &apos;어떻게 대응할지&apos;를 알려줍니다
              </p>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}

