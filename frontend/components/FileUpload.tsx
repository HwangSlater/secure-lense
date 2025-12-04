'use client'

import { useState, useCallback, useEffect } from 'react'

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

interface FileUploadProps {
  onAnalysisComplete: (data: AnalysisData) => void
  onAiAnalysisLoaded?: (analysis: string) => void
}

export default function FileUpload({ onAnalysisComplete, onAiAnalysisLoaded }: FileUploadProps) {
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState('')
  const [autoAi, setAutoAi] = useState(false)
  const [canUseAi, setCanUseAi] = useState(true)
  const [showEmailInputs, setShowEmailInputs] = useState(false)
  const [emailSubject, setEmailSubject] = useState('')
  const [emailContent, setEmailContent] = useState('')

  useEffect(() => {
    const role = localStorage.getItem('role')
    const credits = parseInt(localStorage.getItem('credits') || '0', 10)
    if (role !== 'ADMIN' && credits <= 0) {
      setCanUseAi(false)
      setAutoAi(false)
    }
  }, [])

  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragging(false)
  }, [])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
  }, [])

  const uploadFile = async (file: File) => {
    setError('')
    setUploading(true)
    setProgress(0)

    // Validate file size (50MB)
    if (file.size > 50 * 1024 * 1024) {
      setError('파일 크기는 50MB를 초과할 수 없습니다.')
      setUploading(false)
      return
    }

    // Validate extension
    const allowedExtensions = ['.exe', '.dll', '.pdf', '.docx', '.eml', '.zip']
    const ext = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
    if (!allowedExtensions.includes(ext)) {
      setError('지원하지 않는 파일 형식입니다. (.exe, .dll, .pdf, .docx, .eml만 가능)')
      setUploading(false)
      return
    }

    try {
      const formData = new FormData()
      formData.append('file', file)

      const token = localStorage.getItem('token')
      const xhr = new XMLHttpRequest()

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const percentComplete = Math.round((e.loaded / e.total) * 100)
          setProgress(percentComplete)
        }
      })

      xhr.onload = async () => {
        if (xhr.status === 200) {
          const data: AnalysisData = JSON.parse(xhr.responseText)
          onAnalysisComplete(data)
          setProgress(100)

          // Save email info to localStorage for later use in AI analysis
          if (showEmailInputs && (emailSubject.trim() || emailContent.trim())) {
            localStorage.setItem(`email_info_${data.scan_id}`, JSON.stringify({
              subject: emailSubject.trim(),
              content: emailContent.trim()
            }))
          }

          // Optional: auto-run Gemini AI deep analysis if requested
          if (autoAi && onAiAnalysisLoaded) {
            try {
              const apiUrl = `${process.env.NEXT_PUBLIC_API_URL || ''}/analysis/ai`
              const requestBody: any = { scan_id: data.scan_id }
              if (emailSubject.trim()) {
                requestBody.email_subject = emailSubject.trim()
              }
              if (emailContent.trim()) {
                requestBody.email_content = emailContent.trim()
              }
              
              const aiResponse = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(requestBody),
              })

              const aiData = await aiResponse.json()

              if (aiResponse.ok) {
                if (typeof aiData.analysis === 'string') {
                  onAiAnalysisLoaded(aiData.analysis)
                }
                if (typeof aiData.remaining_credits === 'number') {
                  localStorage.setItem('credits', aiData.remaining_credits.toString())
                }
              } else if (aiResponse.status === 402) {
                setError(aiData.detail || 'AI 심층 분석을 사용하려면 분석 티켓이 필요합니다.')
              } else if (aiData.detail) {
                setError(aiData.detail)
              } else {
                setError('AI 심층 분석 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
              }
            } catch (err: any) {
              setError('AI 심층 분석 요청 중 문제가 발생했습니다. 잠시 후 다시 시도해주세요.')
            }
          }
        } else {
          try {
            const errorData = JSON.parse(xhr.responseText)
            setError(errorData.detail || '파일 업로드 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
          } catch {
            if (xhr.status === 0) {
              setError('서버에 연결할 수 없습니다. 네트워크 연결을 확인해주세요.')
            } else if (xhr.status >= 500) {
              setError('서버에서 문제가 발생했습니다. 잠시 후 다시 시도해주세요.')
            } else {
              setError('파일 업로드 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
            }
          }
        }
        setUploading(false)
      }

      xhr.onerror = () => {
        setError('서버에 연결할 수 없습니다. 네트워크 연결을 확인해주세요.')
        setUploading(false)
      }

      xhr.open('POST', `${process.env.NEXT_PUBLIC_API_URL || ''}/files/upload`)
      xhr.setRequestHeader('Authorization', `Bearer ${token}`)
      xhr.send(formData)

    } catch (err: any) {
      setError('파일 업로드 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.')
      setUploading(false)
    }
  }

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault()
      e.stopPropagation()
      setDragging(false)

      const files = Array.from(e.dataTransfer.files)
      if (files.length > 0) {
        await uploadFile(files[0])
      }
    },
    []
  )

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files
    if (files && files.length > 0) {
      await uploadFile(files[0])
    }
  }

  return (
    <div className="bg-slate-900/70 rounded-lg shadow-lg p-8 border border-slate-700">
      <h2 className="text-2xl font-bold mb-2 text-slate-50">파일 분석</h2>
      <p className="text-sm text-slate-300 mb-4">
        의심되는 이메일 첨부파일이나 실행 파일을 업로드하면, 여러 보안 엔진과 규칙으로 자동 분석합니다.
      </p>
      <div className="mb-6 space-y-4">
        <div className="flex items-start space-x-2">
          <input
            id="email-info-check"
            type="checkbox"
            className="mt-1 h-4 w-4 text-cyan-500 border-slate-500 rounded bg-slate-900"
            checked={showEmailInputs}
            onChange={(e) => setShowEmailInputs(e.target.checked)}
          />
          <div>
            <label htmlFor="email-info-check" className="text-sm font-medium text-slate-100">
              이메일 정보 추가 (선택사항)
            </label>
            <p className="text-xs text-slate-300 mt-1">
              이메일 파일(.eml)인 경우, 제목과 내용을 입력하면 AI 분석 정확도가 향상됩니다.
            </p>
          </div>
        </div>

        {showEmailInputs && (
          <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700 space-y-3">
            <div>
              <label htmlFor="email-subject" className="block text-sm font-medium text-slate-200 mb-1">
                이메일 제목
              </label>
              <input
                id="email-subject"
                type="text"
                value={emailSubject}
                onChange={(e) => setEmailSubject(e.target.value)}
                placeholder="예: 긴급 보안 업데이트 안내"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-md text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                disabled={uploading}
              />
            </div>
            <div>
              <label htmlFor="email-content" className="block text-sm font-medium text-slate-200 mb-1">
                이메일 내용
              </label>
              <textarea
                id="email-content"
                value={emailContent}
                onChange={(e) => setEmailContent(e.target.value)}
                placeholder="이메일 본문 내용을 입력하세요..."
                rows={4}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-md text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent resize-none"
                disabled={uploading}
              />
            </div>
          </div>
        )}
      </div>

      <div
        className={`border-2 border-dashed rounded-lg p-12 text-center transition-colors ${
          dragging
            ? 'border-cyan-400 bg-cyan-500/5'
            : uploading
            ? 'border-slate-600 bg-slate-900/50'
            : 'border-slate-600 hover:border-cyan-400 hover:bg-slate-900/40'
        }`}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        {uploading ? (
          <div className="space-y-4">
            <div className="flex justify-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400"></div>
            </div>
            <p className="text-lg font-medium text-slate-100">분석 중... (약 30초 소요)</p>
            <div className="w-full bg-slate-800 rounded-full h-2.5">
              <div
                className="bg-cyan-400 h-2.5 rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
            <p className="text-sm text-slate-300">{progress}%</p>
          </div>
        ) : (
          <>
            <svg
              className="mx-auto h-16 w-16 text-cyan-300 mb-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
              />
            </svg>
            <p className="text-lg font-medium text-slate-50 mb-2">
              파일을 여기에 드래그하거나 클릭하여 업로드하세요
            </p>
            <p className="text-sm text-slate-300 mb-4">
              지원 형식: EXE, DLL, PDF, DOCX, EML (최대 50MB)
            </p>
            <label className="inline-block bg-cyan-500 text-slate-900 font-semibold px-6 py-2 rounded-md hover:bg-cyan-400 cursor-pointer">
              파일 선택
              <input
                type="file"
                className="hidden"
                onChange={handleFileSelect}
                accept=".exe,.dll,.pdf,.docx,.eml,.zip"
              />
            </label>
          </>
        )}
      </div>

      {error && (
        <div className="mt-4 bg-red-900/40 border border-red-500/70 text-red-100 px-4 py-3 rounded text-sm">
          {error}
        </div>
      )}

      <div className="mt-4 flex items-start space-x-2">
        <input
          id="auto-ai"
          type="checkbox"
          className="mt-1 h-4 w-4 text-cyan-500 border-slate-500 rounded bg-slate-900"
          checked={autoAi}
          disabled={!canUseAi}
          onChange={(e) => setAutoAi(e.target.checked)}
        />
        <div>
          <label htmlFor="auto-ai" className="text-sm font-medium text-slate-100">
            파일 업로드 후 Gemini AI 심층 분석까지 함께 실행
          </label>
          <p className="text-xs text-slate-300 mt-1">
            AI 심층 분석 1회당 티켓 1개가 사용됩니다. 관리자이거나 보유 티켓이 1개 이상일 때만 선택할 수 있습니다.
          </p>
          {!canUseAi && (
            <p className="text-xs text-red-300 mt-1">
              보유 티켓이 없습니다. 티켓을 충전한 후 다시 시도해주세요.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

