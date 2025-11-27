import { useState, useEffect } from 'react'
import { api } from '../utils/api'
import { useToast } from '../contexts/ToastContext'

export default function DeviceEnrollment({ userId, onEnrollmentComplete, onBack }) {
  const [deviceId, setDeviceId] = useState('')
  const [isEnrolling, setIsEnrolling] = useState(false)
  const [enrolledDevices, setEnrolledDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const { showToast } = useToast()

  useEffect(() => {
    if (userId) {
      loadUserDevices()
    }
  }, [userId])

  useEffect(() => {
    // Auto-generate device ID based on browser fingerprint
    const generateDeviceId = () => {
      const userAgent = navigator.userAgent
      const platform = navigator.platform
      const language = navigator.language
      const fingerprint = `${userAgent}-${platform}-${language}`
      
      // Hash to create shorter ID
      const hash = Array.from(fingerprint)
        .reduce((hash, char) => {
          return ((hash << 5) - hash) + char.charCodeAt(0)
        }, 0)
      
      return `device_${Math.abs(hash).toString(16)}_${Date.now()}`
    }

    setDeviceId(generateDeviceId())
  }, [])

  const loadUserDevices = async () => {
    if (!userId) {
      console.log('[DeviceEnrollment] No userId, skipping device load')
      setLoading(false)
      return
    }
    
    try {
      setLoading(true)
      console.log('[DeviceEnrollment] Loading devices for user:', userId)
      const result = await api.getUserDevices(userId)
      console.log('[DeviceEnrollment] Devices loaded:', result)
      setEnrolledDevices(result.devices || [])
      console.log('[DeviceEnrollment] Set enrolled devices:', result.devices?.length || 0, 'devices')
    } catch (error) {
      console.error('[DeviceEnrollment] Failed to load devices:', error)
      showToast('Failed to load devices: ' + error.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleEnrollDevice = async (e) => {
    e.preventDefault()
    
    if (!deviceId.trim()) {
      showToast('Please enter a device ID', 'error')
      return
    }

    setIsEnrolling(true)
    
    try {
      console.log('[DeviceEnrollment] Enrolling device:', deviceId, 'for user:', userId)
      
      // Call enrollment API
      const result = await api.enrollDevice(deviceId, userId)
      
      console.log('[DeviceEnrollment] API response:', result)
      
      if (result.success) {
        const tpmMode = result.tpm_info?.mode || 'unknown'
        console.log('[DeviceEnrollment] ✓ Device enrolled successfully, TPM mode:', tpmMode)
        
        showToast(`✓ Device enrolled successfully! (${tpmMode})`, 'success')
        
        // Reload devices list
        await loadUserDevices()
        
        // Notify parent component
        if (onEnrollmentComplete) {
          setTimeout(() => {
            onEnrollmentComplete(deviceId)
          }, 1500)
        }
      } else {
        throw new Error(result.error || 'Enrollment failed')
      }
    } catch (error) {
      console.error('[DeviceEnrollment] Enrollment failed:', error)
      const errorMsg = error.response?.data?.detail || error.message || 'Enrollment failed'
      showToast(`✗ Enrollment failed: ${errorMsg}`, 'error')
    } finally {
      setIsEnrolling(false)
    }
  }

  const handleRevokeDevice = async (deviceIdToRevoke) => {
    if (!confirm(`Are you sure you want to revoke device ${deviceIdToRevoke}?`)) {
      return
    }

    try {
      await api.revokeDevice(deviceIdToRevoke, 'User revoked via UI')
      showToast('Device revoked successfully', 'success')
      await loadUserDevices()
    } catch (error) {
      console.error('[DeviceEnrollment] Revocation failed:', error)
      showToast(`Device revocation failed: ${error.message}`, 'error')
    }
  }

  const getDeviceStatus = (device) => {
    const status = device.status || 'unknown'
    const colors = {
      active: 'bg-green-500',
      revoked: 'bg-red-500',
      unknown: 'bg-gray-500'
    }
    return colors[status] || colors.unknown
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 rounded-2xl shadow-2xl p-8 border border-purple-500/30">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-purple-600/20 rounded-xl flex items-center justify-center">
              <svg className="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white">Device Enrollment</h2>
              <p className="text-purple-300 text-sm">Register this device with TPM attestation</p>
            </div>
          </div>
          
          {/* Refresh Button */}
          <button
            onClick={loadUserDevices}
            disabled={loading}
            className="px-4 py-2 bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 rounded-lg text-purple-300 transition-colors disabled:opacity-50"
            title="Refresh devices list"
          >
            <svg className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </div>

        {/* Enrollment Form */}
        <form onSubmit={handleEnrollDevice} className="mb-8">
          <div className="space-y-4">
            <div>
              <label className="block text-purple-200 mb-2 text-sm font-medium">
                Device ID
              </label>
              <input
                type="text"
                value={deviceId}
                onChange={(e) => setDeviceId(e.target.value)}
                className="w-full px-4 py-3 bg-black/30 border border-purple-500/30 rounded-lg text-white placeholder-purple-300/50 focus:outline-none focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20"
                placeholder="Auto-generated device identifier"
                disabled={isEnrolling}
              />
              <p className="text-purple-400/70 text-xs mt-1">
                This ID identifies your device uniquely. It's based on your browser fingerprint.
              </p>
            </div>

            <div className="bg-purple-900/20 border border-purple-500/30 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <svg className="w-5 h-5 text-purple-400 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div className="text-sm text-purple-200">
                  <p className="font-medium mb-2">🔐 Why enroll a device?</p>
                  <p className="text-purple-300/80 mb-2 text-xs">
                    <strong>Without device enrollment:</strong> Anyone with your password can login from anywhere.
                  </p>
                  <p className="text-purple-300/80 mb-2 text-xs">
                    <strong>With device enrollment:</strong> Login requires BOTH password + your enrolled device (2FA-like hardware binding).
                  </p>
                  <p className="text-purple-400/70 text-xs italic">
                    Think of it as: Password = what you know, Device = what you have
                  </p>
                </div>
              </div>
            </div>

            <div className="flex gap-3">
              {onBack && (
                <button
                  type="button"
                  onClick={onBack}
                  disabled={isEnrolling}
                  className="flex-1 py-4 rounded-lg font-semibold text-green-300 bg-black/30 border border-green-500/30 hover:bg-black/50 transition-all disabled:opacity-50"
                >
                  ← Back to Home
                </button>
              )}
              <button
                type="submit"
                disabled={isEnrolling || !deviceId.trim() || !userId}
                className={`flex-1 py-4 rounded-lg font-semibold text-white transition-all duration-200 ${
                  isEnrolling || !deviceId.trim() || !userId
                    ? 'bg-gray-600 cursor-not-allowed opacity-50'
                    : 'bg-gradient-to-r from-green-600 to-teal-600 hover:from-green-700 hover:to-teal-700 shadow-lg hover:shadow-green-500/50'
                }`}
              >
                {isEnrolling ? (
                  <span className="flex items-center justify-center gap-2">
                    <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Enrolling Device...
                  </span>
                ) : (
                  '🔐 Enroll This Device'
                )}
              </button>
            </div>
          </div>
        </form>

        {/* Next Steps Guide */}
        {enrolledDevices.length > 0 && (
          <div className="mb-8 bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div className="text-sm text-blue-200">
                <p className="font-medium mb-2">✓ Device enrolled! Next steps:</p>
                <ol className="space-y-1 text-blue-300/80 text-xs list-decimal list-inside">
                  <li>Go back to home</li>
                  <li>Click "Hardware Login" button</li>
                  <li>Enter your User ID: <span className="font-semibold text-white">{userId}</span></li>
                  <li>Enter your Device ID: <span className="font-semibold text-white">{enrolledDevices[0]?.device_id}</span></li>
                  <li>Enter your password</li>
                  <li>Authenticate with TPM attestation + zkSNARK proof! 🔐</li>
                </ol>
              </div>
            </div>
          </div>
        )}

        {/* Enrolled Devices List */}
        <div>
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Your Enrolled Devices
          </h3>

          <div className="mb-4">
            <p className="text-sm text-purple-400">
              User: <span className="font-semibold text-white">{userId}</span>
              {' • '}
              Devices: <span className="font-semibold text-white">{enrolledDevices.length}</span>
            </p>
          </div>

          {loading ? (
            <div className="text-center py-8 text-purple-300">
              <svg className="animate-spin h-8 w-8 mx-auto mb-2" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              <p>Loading devices...</p>
            </div>
          ) : enrolledDevices.length === 0 ? (
            <div className="bg-black/20 border border-purple-500/20 rounded-lg p-6 text-center">
              <svg className="w-12 h-12 text-purple-400/50 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <p className="text-purple-300 mb-2">No devices enrolled yet</p>
              <p className="text-purple-400/70 text-sm">Enroll your first device to enable hardware-attested authentication</p>
            </div>
          ) : (
            <div className="space-y-3">
              {enrolledDevices.map((device) => (
                <div
                  key={device.device_id}
                  className="bg-black/30 border border-purple-500/30 rounded-lg p-4 hover:border-purple-500/50 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full ${getDeviceStatus(device)}`} />
                      <div>
                        <p className="text-white font-medium">{device.device_id}</p>
                        <p className="text-purple-300 text-xs">
                          Enrolled: {new Date(device.enrolled_at * 1000).toLocaleString()}
                        </p>
                        {device.tpm_info && (
                          <p className="text-purple-400 text-xs">
                            TPM Mode: {device.tpm_info.mode}
                          </p>
                        )}
                      </div>
                    </div>
                    {device.status === 'active' && (
                      <button
                        onClick={() => handleRevokeDevice(device.device_id)}
                        className="px-3 py-1 bg-red-600/20 hover:bg-red-600/30 border border-red-500/50 rounded text-red-400 text-sm transition-colors"
                      >
                        Revoke
                      </button>
                    )}
                    {device.status === 'revoked' && (
                      <span className="px-3 py-1 bg-red-600/20 border border-red-500/50 rounded text-red-400 text-sm">
                        Revoked
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

