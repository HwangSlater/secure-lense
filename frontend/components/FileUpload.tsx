'use client'

import { useState, useCallback } from 'react'

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
}

export default function FileUpload({ onAnalysisComplete }: FileUploadProps) {
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState('')

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

      xhr.onload = () => {
        if (xhr.status === 200) {
          const data = JSON.parse(xhr.responseText)
          onAnalysisComplete(data)
          setProgress(100)
        } else {
          try {
            const errorData = JSON.parse(xhr.responseText)
            setError(errorData.detail || '파일 업로드 중 오류가 발생했습니다.')
          } catch {
            setError('파일 업로드 중 오류가 발생했습니다.')
          }
        }
        setUploading(false)
      }

      xhr.onerror = () => {
        setError('파일 업로드 중 오류가 발생했습니다.')
        setUploading(false)
      }

      xhr.open('POST', `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/files/upload`)
      xhr.setRequestHeader('Authorization', `Bearer ${token}`)
      xhr.send(formData)

    } catch (err: any) {
      setError(err.message || '파일 업로드 중 오류가 발생했습니다.')
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
    <div className="bg-white rounded-lg shadow-lg p-8">
      <h2 className="text-2xl font-bold mb-6 text-gray-800">파일 분석</h2>

      <div
        className={`border-2 border-dashed rounded-lg p-12 text-center transition-colors ${
          dragging
            ? 'border-blue-500 bg-blue-50'
            : uploading
            ? 'border-gray-300 bg-gray-50'
            : 'border-gray-300 hover:border-blue-400 hover:bg-gray-50'
        }`}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        {uploading ? (
          <div className="space-y-4">
            <div className="flex justify-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
            <p className="text-lg font-medium text-gray-700">분석 중... (약 30초 소요)</p>
            <div className="w-full bg-gray-200 rounded-full h-2.5">
              <div
                className="bg-blue-600 h-2.5 rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
            <p className="text-sm text-gray-500">{progress}%</p>
          </div>
        ) : (
          <>
            <svg
              className="mx-auto h-16 w-16 text-gray-400 mb-4"
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
            <p className="text-lg font-medium text-gray-700 mb-2">
              파일을 여기에 드래그하거나 클릭하여 업로드하세요
            </p>
            <p className="text-sm text-gray-500 mb-4">
              지원 형식: EXE, DLL, PDF, DOCX, EML (최대 50MB)
            </p>
            <label className="inline-block bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 cursor-pointer">
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
        <div className="mt-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
          {error}
        </div>
      )}
    </div>
  )
}

