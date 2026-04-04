import { useState } from 'react'
import { api } from '../utils/api'
import { hashPasswordToField, computeCommitment, reduceToField } from '../utils/crypto'
import { useToast } from '../contexts/ToastContext'
import PasswordStrength from './PasswordStrength'

// Persist device fingerprint in localStorage so it survives page refreshes
const getOrCreateDeviceId = (userId) => {
  const key = `chaotic_device_${userId}`
  let stored = localStorage.getItem(key)
  if (!stored) {
    const fingerprint = `${navigator.userAgent}-${navigator.platform}-${navigator.language}`
    const hash = Array.from(fingerprint)
      .reduce((h, c) => (((h << 5) - h) + c.charCodeAt(0)) | 0, 0)
    stored = `device_${Math.abs(hash).toString(16)}`
    localStorage.setItem(key, stored)
  }
  return stored
}

// Detect ?odoo=true URL param
const isOdooFlow = new URLSearchParams(window.location.search).get('odoo') === 'true'
const CHAOTIC_API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function Registration({ onBack, onSuccess }) {
  const [hrId, setHrId] = useState('')
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [odooStep, setOdooStep] = useState('')
  const toast = useToast()

  const handleSubmit = async (e) => {
    e.preventDefault()

    if (!hrId.trim()) {
      toast.error('Username cannot be empty')
      return
    }

    if (!password) {
      toast.error('Password cannot be empty')
      return
    }

    if (password !== confirmPassword) {
      toast.error('Passwords do not match')
      return
    }

    setLoading(true)

    try {
      console.log('[Registration] Requesting g0 from server...')
      toast.info('Generating cryptographic parameters...')
      const { g0 } = await api.getG0()

      const secretX = await hashPasswordToField(password)
      const Y = computeCommitment(g0, secretX)

      await api.register(hrId, Y.toString(), g0)
      toast.success('✓ Account created! Enrolling device...')

      // Persist device ID and enroll
      const deviceId = getOrCreateDeviceId(hrId)
      try {
        await api.enrollDevice(deviceId, hrId)
        toast.success('✓ Device enrolled!')
      } catch (enrollError) {
        console.error('[Registration] Device enrollment failed:', enrollError)
        toast.warning('Account created but device enrollment failed')
      }

      // If launched from Odoo (?odoo=true), provision an Odoo account too
      if (isOdooFlow && email) {
        setOdooStep('Provisioning Odoo account...')
        try {
          const odooRes = await fetch(`${CHAOTIC_API}/api/register/odoo`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hr_id: hrId, email, full_name: fullName }),
          })
          const odooJson = await odooRes.json()
          if (odooJson.success) {
            toast.success('✓ Odoo account ready! Redirecting back...')
            setTimeout(() => { window.location.href = 'http://localhost:8069/web/login' }, 2000)
            return
          } else {
            toast.warning(`Odoo provisioning: ${odooJson.detail || 'failed'}`)
          }
        } catch (odooErr) {
          console.error('[Registration] Odoo provisioning error:', odooErr)
          toast.warning('Odoo account provisioning failed — you can still use Chaotic login.')
        }
        setOdooStep('')
      }

      setTimeout(() => onSuccess(), 2000)
    } catch (err) {
      console.error('[Registration] Error:', err)
      toast.error(err.message || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card p-8 max-w-md mx-auto relative overflow-hidden">
      {/* Decorative gradient */}
      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-primary-500 via-purple-500 to-pink-500"></div>

      <div className="mb-6">
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2 bg-primary-500 bg-opacity-20 rounded-lg">
            <svg className="w-6 h-6 text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-white">Register</h2>
        </div>
        <p className="text-gray-400 text-sm">
          {isOdooFlow
            ? '🏢 Creating your Chaotic account for Odoo login'
            : 'Create a new account with zero-knowledge authentication'}
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Odoo-flow extra fields */}
        {isOdooFlow && (
          <>
            <div>
              <label className="label">Full Name</label>
              <input type="text" value={fullName} onChange={e => setFullName(e.target.value)}
                className="input-field" placeholder="Your display name" disabled={loading} />
            </div>
            <div>
              <label className="label">Email (Odoo login)</label>
              <input type="email" value={email} onChange={e => setEmail(e.target.value)}
                className="input-field" placeholder="you@example.com" disabled={loading} required />
            </div>
          </>
        )}
        <div>
          <label className="label">Username (HR_ID)</label>
          <input
            type="text"
            value={hrId}
            onChange={(e) => setHrId(e.target.value)}
            className="input-field"
            placeholder="Enter username"
            disabled={loading}
          />
        </div>

        <div>
          <label className="label">Password</label>
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input-field pr-12"
              placeholder="Enter password"
              disabled={loading}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
              disabled={loading}
            >
              {showPassword ? (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                </svg>
              ) : (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
              )}
            </button>
          </div>
          <PasswordStrength password={password} />
        </div>

        <div>
          <label className="label">Confirm Password</label>
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="input-field pr-12"
              placeholder="Confirm password"
              disabled={loading}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
              disabled={loading}
            >
              {showPassword ? (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                </svg>
              ) : (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
              )}
            </button>
          </div>
          {confirmPassword && (
            <div className="mt-2 flex items-center gap-2 text-xs">
              {password === confirmPassword ? (
                <>
                  <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  <span className="text-green-400">Passwords match</span>
                </>
              ) : (
                <>
                  <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                  <span className="text-red-400">Passwords do not match</span>
                </>
              )}
            </div>
          )}
        </div>

        <div className="pt-4 space-y-3">
          <button
            type="submit"
            disabled={loading}
            className="w-full btn-primary"
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Processing...
              </span>
            ) : (
              'Register'
            )}
          </button>

          <button
            type="button"
            onClick={onBack}
            disabled={loading}
            className="w-full btn-secondary"
          >
            Back
          </button>
        </div>
      </form>

      <div className="mt-6 pt-6 border-t border-gray-700 border-opacity-50">
        <div className="flex items-start gap-3 bg-primary-500 bg-opacity-10 border border-primary-500 border-opacity-30 rounded-lg p-3">
          <svg className="w-5 h-5 text-primary-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-xs text-gray-300 leading-relaxed">
            Your password is hashed in the browser and never sent to the server.
            Only a cryptographic commitment is stored.
          </p>
        </div>
      </div>
    </div>
  )
}

export default Registration

