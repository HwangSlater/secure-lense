'use client'

import { useState } from 'react'

interface CreditChargeProps {
  onCreditsUpdated: () => void
}

export default function CreditCharge({ onCreditsUpdated }: CreditChargeProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [amount, setAmount] = useState(5)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const handleCharge = async () => {
    setError('')
    setSuccess('')
    setLoading(true)

    try {
      const token = localStorage.getItem('token')
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/credits/charge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ amount }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || '티켓 충전에 실패했습니다.')
      }

      setSuccess(data.message)
      localStorage.setItem('credits', data.new_balance.toString())
      onCreditsUpdated()

      setTimeout(() => {
        setIsOpen(false)
        setSuccess('')
      }, 2000)
    } catch (err: any) {
      setError(err.message || '티켓 충전에 실패했습니다.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <button
        onClick={() => setIsOpen(true)}
        className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
      >
        충전하기
      </button>

      {isOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 max-w-md w-full mx-4">
            <h3 className="text-xl font-bold mb-4 text-gray-800">분석 티켓 충전</h3>

            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                충전할 티켓 수
              </label>
              <input
                type="number"
                min="1"
                max="100"
                value={amount}
                onChange={(e) => setAmount(parseInt(e.target.value) || 1)}
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {error && (
              <div className="mb-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
                {error}
              </div>
            )}

            {success && (
              <div className="mb-4 bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded">
                {success}
              </div>
            )}

            <div className="flex space-x-3">
              <button
                onClick={handleCharge}
                disabled={loading || amount < 1}
                className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? '충전 중...' : '충전하기'}
              </button>
              <button
                onClick={() => {
                  setIsOpen(false)
                  setError('')
                  setSuccess('')
                }}
                className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-md hover:bg-gray-400"
              >
                취소
              </button>
            </div>

            <p className="mt-4 text-xs text-gray-500 text-center">
              * 이는 모의 결제 시스템입니다. 실제 결제가 발생하지 않습니다.
            </p>
          </div>
        </div>
      )}
    </>
  )
}

