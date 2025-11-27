import { useState } from 'react'
import Modal from './Modal'

export default function EnrollDeviceModal({ isOpen, onClose, onEnroll }) {
  const [userId, setUserId] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    if (!userId.trim()) {
      return
    }

    setIsSubmitting(true)
    try {
      await onEnroll(userId.trim())
      setUserId('')
    } catch (error) {
      console.error('Enrollment error:', error)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleClose = () => {
    if (!isSubmitting) {
      setUserId('')
      onClose()
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={handleClose} showCloseButton={!isSubmitting}>
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Icon */}
        <div className="flex justify-center">
          <div className="w-16 h-16 bg-green-600/20 rounded-2xl flex items-center justify-center">
            <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
        </div>

        {/* Title */}
        <div className="text-center">
          <h2 className="text-2xl font-bold text-white mb-2">
            Device Enrollment
          </h2>
          <p className="text-purple-300 text-sm">
            Register your device with TPM attestation
          </p>
        </div>

        {/* Input */}
        <div>
          <label className="block text-purple-200 mb-2 text-sm font-medium">
            User ID
          </label>
          <input
            type="text"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            disabled={isSubmitting}
            className="w-full px-4 py-3 bg-black/30 border border-purple-500/30 rounded-lg text-white placeholder-purple-300/50 focus:outline-none focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 disabled:opacity-50"
            placeholder="Enter your registered user ID"
            autoFocus
            required
          />
          <p className="text-purple-400/70 text-xs mt-2">
            💡 Use the same username you registered with
          </p>
        </div>

        {/* Info Box */}
        <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div className="text-sm text-green-200">
              <p className="font-medium mb-2">What happens next:</p>
              <ul className="space-y-1 text-green-300/80 text-xs">
                <li>✓ Device key generated in TPM</li>
                <li>✓ Device certificate issued</li>
                <li>✓ PCR baseline captured</li>
                <li>✓ Enrollment logged to audit trail</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Buttons */}
        <div className="flex gap-3">
          <button
            type="button"
            onClick={handleClose}
            disabled={isSubmitting}
            className="flex-1 py-3 rounded-lg font-semibold text-purple-300 bg-black/30 border border-purple-500/30 hover:bg-black/50 transition-all disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isSubmitting || !userId.trim()}
            className={`flex-1 py-3 rounded-lg font-semibold text-white transition-all duration-200 ${
              isSubmitting || !userId.trim()
                ? 'bg-gray-600 cursor-not-allowed'
                : 'bg-gradient-to-r from-green-600 to-teal-600 hover:from-green-700 hover:to-teal-700 shadow-lg hover:shadow-green-500/50'
            }`}
          >
            {isSubmitting ? (
              <span className="flex items-center justify-center gap-2">
                <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Enrolling...
              </span>
            ) : (
              'Enroll Device'
            )}
          </button>
        </div>
      </form>
    </Modal>
  )
}

