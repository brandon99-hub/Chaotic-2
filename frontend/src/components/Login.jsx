import { useState } from 'react'
import { api } from '../utils/api'
import { hashPasswordToField } from '../utils/crypto'
import { generateProof } from '../utils/snarkProof'
import { useToast } from '../contexts/ToastContext'

// Persist device fingerprint per user in localStorage
const getOrCreateDeviceId = (userId) => {
  if (!userId) {
    // Pre-login: use a temporary fingerprint; it will be locked to the user on first enroll
    const fingerprint = `${navigator.userAgent}-${navigator.platform}-${navigator.language}`
    const hash = Array.from(fingerprint).reduce((h, c) => (((h << 5) - h) + c.charCodeAt(0)) | 0, 0)
    return `device_${Math.abs(hash).toString(16)}`
  }
  const key = `chaotic_device_${userId}`
  let stored = localStorage.getItem(key)
  if (!stored) {
    const fingerprint = `${navigator.userAgent}-${navigator.platform}-${navigator.language}`
    const hash = Array.from(fingerprint).reduce((h, c) => (((h << 5) - h) + c.charCodeAt(0)) | 0, 0)
    stored = `device_${Math.abs(hash).toString(16)}`
    localStorage.setItem(key, stored)
  }
  return stored
}

function Login({ onBack, onSuccess, hardwareMode = false }) {
  const [hrId, setHrId] = useState('')
  const [password, setPassword] = useState('')
  const [deviceId, setDeviceId] = useState(() => getOrCreateDeviceId(''))
  const [loading, setLoading] = useState(false)
  const [stage, setStage] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const toast = useToast()

  const needsAutoEnroll = (message = '') => {
    const lower = message.toLowerCase()
    return lower.includes('device not enrolled') ||
      lower.includes('device revoked') ||
      lower.includes('device not found') ||
      lower.includes('does not belong to user')
  }

  const requestHardwareChallenge = async (retry = true) => {
    // Resolve the persistent device ID now that we know the hrId
    const persistedDeviceId = getOrCreateDeviceId(hrId)
    try {
      return await api.requestChallenge(hrId, persistedDeviceId)
    } catch (err) {
      if (retry && hardwareMode && needsAutoEnroll(err.message || '')) {
        toast.info('Pairing this device to your account…')
        await api.enrollDevice(persistedDeviceId, hrId)
        return await requestHardwareChallenge(false)
      }
      throw err
    }
  }

  const generateHardwareAttestation = async (challenge, retry = true) => {
    try {
      const attResp = await api.generateDeviceAttestation(
        hrId,
        deviceId,
        challenge.N,
        challenge.t,
        challenge.SRS_ID
      )
      return attResp.attestation
    } catch (attErr) {
      if (retry && hardwareMode && needsAutoEnroll(attErr.message || '')) {
        toast.info('Rebinding TPM keys to this user…')
        await api.enrollDevice(deviceId, hrId)
        return generateHardwareAttestation(challenge, false)
      }
      throw attErr
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setStage('')

    if (!hrId.trim()) {
      toast.error('Username cannot be empty')
      return
    }

    if (!password) {
      toast.error('Password cannot be empty')
      return
    }

    // Device ID is auto-generated in hardware mode

    setLoading(true)

    try {
      if (hardwareMode) {
        await handleHardwareLogin()
      } else {
        await handleSimpleLogin()
      }
    } catch (err) {
      console.error('[Login] Error:', err)
      toast.error(err.message || 'Authentication failed. Please check your credentials.')
    } finally {
      setLoading(false)
      setStage('')
    }
  }

  const handleSimpleLogin = async () => {
    setStage('Fetching user data...')
    console.log('[Login] Fetching user data for:', hrId)
    const userData = await api.getUserData(hrId)
    console.log('[Login] Received user data')

    setStage('Hashing password...')
    console.log('[Login] Hashing password...')
    const secretX = await hashPasswordToField(password)
    console.log('[Login] Password hashed')

    setStage('Generating zkSNARK proof... (this may take 10-30 seconds)')
    console.log('[Login] Generating zkSNARK proof...')

    const { proof, publicSignals } = await generateProof(
      BigInt(userData.g0),
      secretX,
      BigInt(userData.Y)
    )

    console.log('[Login] Proof generated successfully')

    setStage('Verifying proof with server...')
    const result = await api.login(hrId, proof, publicSignals)

    console.log('[Login] Authentication successful:', result)
    toast.success(`Welcome back, ${hrId}! Authentication successful.`)

    setTimeout(() => {
      onSuccess(hrId)
    }, 1000)
  }

  const handleHardwareLogin = async () => {
    setStage('Requesting challenge...')
    const challengeResp = await requestHardwareChallenge()
    if (!challengeResp.success) throw new Error(challengeResp.error)
    const challenge = challengeResp.challenge

    setStage('Fetching user data...')
    const userData = await api.getUserData(hrId)

    setStage('Hashing password...')
    const X = await hashPasswordToField(password)

    setStage('Generating TPM attestation...')
    let attestation
    try {
      attestation = await generateHardwareAttestation(challenge)
    } catch (attErr) {
      console.warn('[Login] Falling back to simulated attestation:', attErr)
      toast.warning('Real TPM attestation unavailable, using fallback proof.')
      attestation = await simulateTPMAttestation(challenge.N, challenge.t, challenge.SRS_ID)
    }

    setStage('Generating zkSNARK proof... (10-30s)')
    const { proof, publicSignals } = await generateProof(BigInt(userData.g0), X, BigInt(userData.Y))

    setStage('Verifying with server...')
    const result = await api.verifyAuthentication(hrId, deviceId, challenge.N, attestation, proof, publicSignals)

    if (result.success) {
      toast.success('Hardware-attested login successful!')
      setTimeout(() => onSuccess(hrId, deviceId), 1000)
    }
  }

  const simulateTPMAttestation = async (nonce, timestamp, srsId) => {
    const data = `${nonce}||${timestamp}||${srsId}`
    const enc = new TextEncoder()
    const hash = await crypto.subtle.digest('SHA-256', enc.encode(data))
    const sig = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
    const pcrs = {}
    for (let i of [0, 1, 2, 3, 7]) {
      const pcrHash = await crypto.subtle.digest('SHA-256', enc.encode(`PCR${i}_${deviceId}`))
      pcrs[i] = Array.from(new Uint8Array(pcrHash)).map(b => b.toString(16).padStart(2, '0')).join('')
    }
    return {
      signature: sig,
      pcrs,
      certificate: '-----BEGIN CERTIFICATE-----\nSimulated\n-----END CERTIFICATE-----',
      nonce: String(nonce),
      timestamp,
      srs_id: srsId,
      tpm_mode: 'simulation'
    }
  }

  return (
    <div className="card p-8 max-w-md mx-auto relative overflow-hidden">
      {/* Decorative gradient */}
      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-green-500 via-primary-500 to-purple-500"></div>

      <div className="mb-6">
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2 bg-green-500 bg-opacity-20 rounded-lg">
            <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-white">{hardwareMode ? 'Hardware Login' : 'Login'}</h2>
        </div>
        <p className="text-gray-400 text-sm">{hardwareMode ? 'TPM Attestation + zkSNARK' : 'Authenticate with zero-knowledge proof'}</p>
      </div>

      {stage && (
        <div className="mb-4 p-4 bg-primary-500 bg-opacity-20 border border-primary-500 border-opacity-50 rounded-lg text-primary-200 backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <svg className="animate-spin h-5 w-5 text-primary-400 flex-shrink-0" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span className="text-sm font-medium">{stage}</span>
          </div>
          {stage.includes('zkSNARK') && (
            <div className="mt-2 pt-2 border-t border-primary-500 border-opacity-30">
              <p className="text-xs text-primary-300 opacity-75">
                ⏱️ This may take 10-30 seconds depending on your device...
              </p>
            </div>
          )}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
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
        </div>

        {hardwareMode && (
          <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-3">
            <div className="flex items-start gap-2">
              <svg className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div className="text-xs text-blue-200">
                <p className="font-medium mb-1">🔐 Hardware-Attested Login</p>
                <p className="text-blue-300/80">
                  This device: <span className="font-mono text-white text-[10px]">{deviceId}</span>
                </p>
                <p className="text-blue-400/70 mt-1">Auto-detected from browser fingerprint</p>
              </div>
            </div>
          </div>
        )}

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
                Authenticating...
              </span>
            ) : (
              hardwareMode ? 'Login with Attestation' : 'Login'
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
        <div className="flex items-start gap-3 bg-green-500 bg-opacity-10 border border-green-500 border-opacity-30 rounded-lg p-3">
          <svg className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-xs text-gray-300 leading-relaxed">
            Your browser will generate a zkSNARK proof that you know the password
            without revealing it. The proof generation may take 10-30 seconds.
          </p>
        </div>
      </div>
    </div>
  )
}

export default Login

