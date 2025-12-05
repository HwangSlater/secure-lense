'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import FileUpload from '@/components/FileUpload'
import URLAnalyzer from '@/components/URLAnalyzer'
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
  const [activeTab, setActiveTab] = useState<'file' | 'url' | 'info'>('file')

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
        {/* 탭 네비게이션 */}
        <div className="border-b border-slate-700">
          <nav className="flex space-x-8">
            <button
              onClick={() => setActiveTab('file')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'file'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-300'
              }`}
            >
              파일 분석
            </button>
            <button
              onClick={() => setActiveTab('url')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'url'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-300'
              }`}
            >
              URL 분석
            </button>
            <button
              onClick={() => setActiveTab('info')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'info'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-300'
              }`}
            >
              정보
            </button>
          </nav>
        </div>

        {/* 탭 컨텐츠 */}
        {activeTab === 'file' && (
          <div className="space-y-8">
            {/* File Upload Section */}
            <FileUpload
              onAnalysisComplete={handleAnalysisComplete}
              onAiAnalysisLoaded={handleAiAutoLoaded}
            />
          </div>
        )}

        {activeTab === 'url' && (
          <div className="space-y-8">
            {/* URL Analyzer Section */}
            <URLAnalyzer onAnalysisComplete={handleAnalysisComplete} />
          </div>
        )}

        {activeTab === 'info' && (
          <div className="bg-slate-900/70 rounded-lg shadow-lg p-6 border border-slate-700">
            <h2 className="text-2xl font-bold mb-6 text-slate-50">SecureLens 서비스 정보</h2>
            <div className="space-y-6">
              {/* 서비스 소개 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">서비스 소개</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 text-sm text-slate-300 leading-relaxed">
                  <p className="mb-3">
                    SecureLens는 파일과 URL을 분석하여 악성코드 및 피싱 공격을 탐지하는 보안 분석 서비스입니다.
                  </p>
                  <p>
                    다중 엔진 스캔, AI 기반 심층 분석, 외부 위협 인텔리전스 연동을 통해 종합적인 보안 분석을 제공합니다.
                  </p>
                </div>
              </div>

              {/* 주요 기능 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">주요 기능</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 space-y-3 text-sm">
                  <div>
                    <span className="font-semibold text-cyan-300">파일 분석 (다중 엔진)</span>
                    <ul className="mt-1 ml-4 list-disc text-slate-300 space-y-1">
                      <li>ClamAV: 바이러스 시그니처 탐지</li>
                      <li>YARA: 패턴 매칭 규칙 탐지</li>
                      <li>엔트로피 분석: 패킹/암호화 탐지</li>
                      <li>파일 타입 검증: 확장자 위조 탐지</li>
                      <li>PE 헤더 분석: 섹션 이상, API 임포트 분석</li>
                      <li>쉘코드 및 의심 문자열 탐지</li>
                      <li>Office 문서: VBA 매크로, 자동 실행 매크로</li>
                      <li>PDF: JavaScript, 인터랙티브 요소</li>
                      <li>ZIP: 내부 파일, 이중 확장자, 암호화</li>
                      <li>이메일: 스피어피싱 지표 분석</li>
                    </ul>
                  </div>
                  <div>
                    <span className="font-semibold text-cyan-300">URL 분석</span>
                    <ul className="mt-1 ml-4 list-disc text-slate-300 space-y-1">
                      <li>URLScan.io 실시간 스캔</li>
                      <li>악성 URL 탐지 및 위협 점수 평가</li>
                      <li>IP 정보 및 지리적 위치 확인</li>
                    </ul>
                  </div>
                  <div>
                    <span className="font-semibold text-cyan-300">외부 위협 인텔리전스</span>
                    <ul className="mt-1 ml-4 list-disc text-slate-300 space-y-1">
                      <li>VirusTotal: 다수의 백신 엔진 탐지 결과</li>
                      <li>MalwareBazaar: 악성코드 샘플 데이터베이스</li>
                      <li>파일 해시 기반 위협 검증</li>
                    </ul>
                  </div>
                  <div>
                    <span className="font-semibold text-cyan-300">AI 심층 분석</span>
                    <ul className="mt-1 ml-4 list-disc text-slate-300 space-y-1">
                      <li>Google Gemini 2.5 Flash 기반 상세 분석</li>
                      <li>모든 분석 결과를 종합한 종합 평가</li>
                      <li>일반인도 이해하기 쉬운 설명</li>
                      <li>구체적인 대응 방법 및 유사 공격 사례 제시</li>
                    </ul>
                  </div>
                </div>
              </div>

              {/* 위험도 점수 설명 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">위험도 점수 기준</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 space-y-2 text-sm">
                  <div className="flex items-center space-x-3">
                    <span className="px-3 py-1 bg-green-700 text-white rounded text-xs font-semibold">0-20</span>
                    <span className="text-slate-300">매우 낮음: 안전한 파일로 판단됩니다.</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="px-3 py-1 bg-yellow-700 text-white rounded text-xs font-semibold">21-40</span>
                    <span className="text-slate-300">낮음: 주의가 필요할 수 있습니다.</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="px-3 py-1 bg-orange-700 text-white rounded text-xs font-semibold">41-60</span>
                    <span className="text-slate-300">보통: 의심스러운 파일입니다. 신중히 검토하세요.</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="px-3 py-1 bg-red-700 text-white rounded text-xs font-semibold">61-80</span>
                    <span className="text-slate-300">높음: 악성 파일일 가능성이 높습니다.</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="px-3 py-1 bg-red-900 text-white rounded text-xs font-semibold">81-100</span>
                    <span className="text-slate-300">매우 높음: 즉시 삭제하고 조치가 필요합니다.</span>
                  </div>
                </div>
                <div className="mt-3 bg-slate-800/30 rounded-lg p-3 text-xs text-slate-400">
                  <p className="mb-2 font-semibold text-slate-300">주요 점수 항목:</p>
                  <ul className="ml-4 list-disc space-y-1">
                    <li>ClamAV 탐지: +40점</li>
                    <li>YARA 매칭: 최대 +30점</li>
                    <li>엔트로피 7.5 이상: +20점</li>
                    <li>파일 타입 불일치: +15점</li>
                    <li>Office 자동 실행 매크로: +20점</li>
                    <li>VirusTotal 50% 이상 탐지: +25점</li>
                  </ul>
                </div>
              </div>

              {/* 사용 팁 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">사용 팁</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 space-y-2 text-sm text-slate-300">
                  <p>• 이메일 파일(.eml) 분석 시, 제목과 내용을 추가하면 더 정확한 분석이 가능합니다.</p>
                  <p>• AI 심층 분석은 분석 티켓이 필요하며, 더 상세한 설명과 대응 방법을 제공합니다.</p>
                  <p>• 업로드된 파일은 1시간 후 자동으로 삭제됩니다.</p>
                  <p>• 시간당 최대 10개의 파일을 업로드할 수 있습니다.</p>
                </div>
              </div>

              {/* 자주 묻는 질문 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">자주 묻는 질문</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 space-y-4 text-sm text-slate-300">
                  <div>
                    <p className="font-semibold text-slate-200">어떤 파일을 분석할 수 있나요?</p>
                    <p className="mt-1">- 이메일 첨부파일 (.exe, .dll, .pdf, .docx)</p>
                    <p>- 의심스러운 이메일 (.eml)</p>
                  </div>
                  <div>
                    <p className="font-semibold text-slate-200">위험도는 어떻게 계산되나요?</p>
                    <p className="mt-1">- 여러 보안 엔진의 결과를 종합하여 0-100점으로 계산됩니다</p>
                  </div>
                  <div>
                    <p className="font-semibold text-slate-200">AI 분석이 필요한가요?</p>
                    <p className="mt-1">- 기본 분석으로도 위험 여부를 확인할 수 있지만,</p>
                    <p>- AI 분석은 &apos;왜 위험한지&apos;와 &apos;어떻게 대응할지&apos;를 알려줍니다</p>
                  </div>
                </div>
              </div>

              {/* 문의 */}
              <div>
                <h3 className="text-lg font-semibold mb-3 text-slate-200">문의 및 지원</h3>
                <div className="bg-slate-800/50 rounded-lg p-4 text-sm text-slate-300">
                  <p>서비스 관련 문의사항이나 문제가 발생한 경우, 관리자에게 문의해주세요.</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

