'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import FileUpload from '@/components/FileUpload'
import AnalysisResult from '@/components/AnalysisResult'
import AIInsight from '@/components/AIInsight'
import CreditCharge from '@/components/CreditCharge'

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
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/auth/me`, {
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
    setAnalysisData(data)
    setAiAnalysis(null) // Reset AI analysis
  }

  const handleCreditsUpdated = () => {
    fetchUserInfo()
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-xl">로딩 중...</div>
      </div>
    )
  }

  if (!userInfo) {
    return null
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-2xl font-bold text-gray-800">
                SecureLens - 지능형 악성코드 및 스피어피싱 분석
              </h1>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-sm text-gray-600">
                접속자: <span className="font-semibold">{userInfo.username}</span> | 
                보유 티켓: <span className="font-semibold">{userInfo.credits}</span>개
              </div>
              <CreditCharge onCreditsUpdated={handleCreditsUpdated} />
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
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* File Upload Section */}
        <div className="mb-8">
          <FileUpload onAnalysisComplete={handleAnalysisComplete} />
        </div>

        {/* Analysis Results */}
        {analysisData && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Left Column: Technical Analysis */}
            <div>
              <AnalysisResult data={analysisData} />
            </div>

            {/* Right Column: AI Analysis */}
            <div>
              <AIInsight
                scanId={analysisData.scan_id}
                riskScore={analysisData.risk_score}
                riskLevel={analysisData.risk_level}
                aiAnalysis={aiAnalysis}
                onAnalysisLoaded={setAiAnalysis}
              />
            </div>
          </div>
        )}

        {/* Help Section */}
        <div className="mt-12 bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-bold mb-4">❓ 자주 묻는 질문</h2>
          <div className="space-y-4 text-gray-700">
            <div>
              <p className="font-semibold">어떤 파일을 분석할 수 있나요?</p>
              <p className="text-sm">- 이메일 첨부파일 (.exe, .dll, .pdf, .docx)</p>
              <p className="text-sm">- 의심스러운 이메일 (.eml)</p>
            </div>
            <div>
              <p className="font-semibold">위험도는 어떻게 계산되나요?</p>
              <p className="text-sm">- 여러 보안 엔진의 결과를 종합하여 0-100점으로 계산됩니다</p>
            </div>
            <div>
              <p className="font-semibold">AI 분석이 필요한가요?</p>
              <p className="text-sm">- 기본 분석으로도 위험 여부를 확인할 수 있지만,</p>
              <p className="text-sm">- AI 분석은 '왜 위험한지'와 '어떻게 대응할지'를 알려줍니다</p>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}

