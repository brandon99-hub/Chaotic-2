import { useState } from 'react'
import Registration from './components/Registration'
import Login from './components/Login'
import Dashboard from './components/Dashboard'
import DeviceEnrollment from './components/DeviceEnrollment'
import EnrollDeviceModal from './components/EnrollDeviceModal'

function App() {
  const [view, setView] = useState('home')
  const [user, setUser] = useState(null)
  const [showEnrollModal, setShowEnrollModal] = useState(false)
  const [enrollUserId, setEnrollUserId] = useState(null)

  const handleLogout = () => {
    setUser(null)
    setView('home')
  }

  const handleLoginSuccess = (username, deviceId = null) => {
    setUser({ username, deviceId })
    setView('dashboard')
  }

  if (view === 'dashboard' && user) {
    return <Dashboard user={typeof user === 'string' ? user : user.username} onLogout={handleLogout} />
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-4 relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-10 w-72 h-72 bg-primary-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse"></div>
        <div className="absolute top-40 right-20 w-96 h-96 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse" style={{ animationDelay: '2s' }}></div>
        <div className="absolute bottom-20 left-1/3 w-80 h-80 bg-pink-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse" style={{ animationDelay: '4s' }}></div>
      </div>

      <div className="w-full max-w-6xl relative z-10">
        <div className="text-center mb-12">
          <div className="inline-block mb-6 relative">
            <div className="absolute inset-0 bg-gradient-to-r from-primary-500 to-purple-500 blur-2xl opacity-20 animate-pulse"></div>
            <h1 className="text-6xl font-bold mb-2 bg-gradient-to-r from-primary-400 via-purple-400 to-pink-400 bg-clip-text text-transparent relative animate-fade-in">
              zkSNARK + Hardware Auth
            </h1>
          </div>
          <p className="text-2xl text-gray-300 mb-3 font-light">
            Hardware-Attested Passwordless Authentication
          </p>
          <p className="text-sm text-gray-400 max-w-2xl mx-auto leading-relaxed">
            🔒 TPM/TEE attestation + Zero-Knowledge Proofs for maximum security
          </p>
        </div>

        {view === 'home' && (
          <>
            {/* Hero Section */}
            <div className="max-w-6xl mx-auto mb-16">
              <div className="grid md:grid-cols-3 gap-6">
                <button
                  onClick={() => setView('register')}
                  className="group relative overflow-hidden bg-gradient-to-br from-primary-600 to-purple-600 hover:from-primary-500 hover:to-purple-500 text-white font-bold py-6 px-6 rounded-2xl transition-all duration-300 transform hover:scale-105 shadow-2xl hover:shadow-primary-500/50"
                >
                  <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300"></div>
                  <div className="relative">
                    <svg className="w-10 h-10 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
                    </svg>
                    <div className="text-xl mb-1">Register</div>
                    <div className="text-xs opacity-90">Create account</div>
                  </div>
                </button>

                <button
                  onClick={() => setView('login')}
                  className="group relative overflow-hidden bg-gradient-to-br from-gray-700 to-gray-800 hover:from-gray-600 hover:to-gray-700 text-white font-bold py-6 px-6 rounded-2xl transition-all duration-300 transform hover:scale-105 shadow-2xl hover:shadow-gray-500/50"
                >
                  <div className="absolute inset-0 bg-white/10 translate-y-full group-hover:translate-y-0 transition-transform duration-300"></div>
                  <div className="relative">
                    <svg className="w-10 h-10 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                    </svg>
                    <div className="text-xl mb-1">Login</div>
                    <div className="text-xs opacity-90">Simple mode</div>
                  </div>
                </button>

                <button
                  onClick={() => setView('hardware-login')}
                  className="group relative overflow-hidden bg-gradient-to-br from-orange-600 to-red-600 hover:from-orange-500 hover:to-red-500 text-white font-bold py-6 px-6 rounded-2xl transition-all duration-300 transform hover:scale-105 shadow-2xl hover:shadow-orange-500/50"
                >
                  <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300"></div>
                  <div className="relative">
                    <svg className="w-10 h-10 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                    <div className="text-xl mb-1">Hardware Login</div>
                    <div className="text-xs opacity-90">Attested auth</div>
                  </div>
                </button>
              </div>
            </div>

            {/* Features Grid */}
              <div className="grid md:grid-cols-3 gap-6 mb-16">
              <div className="card p-6 hover:shadow-2xl hover:shadow-primary-500/20 transition-all duration-300 transform hover:-translate-y-1">
                <div className="bg-primary-500 bg-opacity-20 w-14 h-14 rounded-lg flex items-center justify-center mb-4">
                  <svg className="w-8 h-8 text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-white mb-2">Zero-Knowledge</h3>
                <p className="text-gray-400 text-sm leading-relaxed">
                  Prove you know your password without ever revealing it. Built on cutting-edge zkSNARK cryptography.
                </p>
              </div>

              <div className="card p-6 hover:shadow-2xl hover:shadow-purple-500/20 transition-all duration-300 transform hover:-translate-y-1">
                <div className="bg-purple-500 bg-opacity-20 w-14 h-14 rounded-lg flex items-center justify-center mb-4">
                  <svg className="w-8 h-8 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-white mb-2">No Storage</h3>
                <p className="text-gray-400 text-sm leading-relaxed">
                  Your password is never stored anywhere. Only cryptographic commitments exist on the server.
                </p>
              </div>

              <div className="card p-6 hover:shadow-2xl hover:shadow-green-500/20 transition-all duration-300 transform hover:-translate-y-1">
                <div className="bg-green-500 bg-opacity-20 w-14 h-14 rounded-lg flex items-center justify-center mb-4">
                  <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-white mb-2">Browser Secure</h3>
                <p className="text-gray-400 text-sm leading-relaxed">
                  All cryptographic operations happen in your browser. Your password never leaves your device.
                </p>
              </div>

              <div className="card p-6 hover:shadow-2xl hover:shadow-orange-500/20 transition-all duration-300 transform hover:-translate-y-1">
                <div className="bg-orange-500 bg-opacity-20 w-14 h-14 rounded-lg flex items-center justify-center mb-4">
                  <svg className="w-8 h-8 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-white mb-2">Hardware Attested</h3>
                <p className="text-gray-400 text-sm leading-relaxed">
                  TPM 2.0 device attestation with PCR verification for hardware-backed trust.
                </p>
              </div>
            </div>

            {/* How It Works */}
            <div className="card p-8 max-w-3xl mx-auto mb-16">
              <h3 className="text-2xl font-bold text-white mb-6 text-center">How It Works</h3>
              <div className="space-y-6">
                <div className="flex items-start gap-4">
                  <div className="flex-shrink-0 w-10 h-10 rounded-full bg-primary-500 bg-opacity-20 flex items-center justify-center text-primary-400 font-bold">
                    1
                  </div>
                  <div>
                    <h4 className="text-white font-semibold mb-1">Random Field Generation</h4>
                    <p className="text-gray-400 text-sm">Server generates a random field element (g0) using a 6D hyper-chaotic system for maximum entropy.</p>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="flex-shrink-0 w-10 h-10 rounded-full bg-primary-500 bg-opacity-20 flex items-center justify-center text-primary-400 font-bold">
                    2
                  </div>
                  <div>
                    <h4 className="text-white font-semibold mb-1">Client-Side Commitment</h4>
                    <p className="text-gray-400 text-sm">Your browser hashes your password and computes a commitment Y = g0 × X mod p using BN254 field arithmetic.</p>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="flex-shrink-0 w-10 h-10 rounded-full bg-primary-500 bg-opacity-20 flex items-center justify-center text-primary-400 font-bold">
                    3
                  </div>
                  <div>
                    <h4 className="text-white font-semibold mb-1">Secure Storage</h4>
                    <p className="text-gray-400 text-sm">Only the commitment is stored on the server. Your actual password never leaves your browser.</p>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="flex-shrink-0 w-10 h-10 rounded-full bg-primary-500 bg-opacity-20 flex items-center justify-center text-primary-400 font-bold">
                    4
                  </div>
                  <div>
                    <h4 className="text-white font-semibold mb-1">zkSNARK Proof Generation</h4>
                    <p className="text-gray-400 text-sm">During login, your browser generates a Groth16 zkSNARK proof that you know X without revealing it.</p>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="flex-shrink-0 w-10 h-10 rounded-full bg-primary-500 bg-opacity-20 flex items-center justify-center text-primary-400 font-bold">
                    5
                  </div>
                  <div>
                    <h4 className="text-white font-semibold mb-1">Hardware Attestation (Optional)</h4>
                    <p className="text-gray-400 text-sm">For maximum security, enroll your device to add TPM attestation with challenge-response protocol.</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Tech Stack */}
            <div className="card p-8 max-w-3xl mx-auto">
              <h3 className="text-2xl font-bold text-white mb-6 text-center">Powered By</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
                <div>
                  <div className="text-3xl font-bold text-primary-400 mb-1">BN254</div>
                  <div className="text-xs text-gray-500 uppercase tracking-wider">Elliptic Curve</div>
                </div>
                <div>
                  <div className="text-3xl font-bold text-purple-400 mb-1">Groth16</div>
                  <div className="text-xs text-gray-500 uppercase tracking-wider">zkSNARK System</div>
                </div>
                <div>
                  <div className="text-3xl font-bold text-green-400 mb-1">SHA-256</div>
                  <div className="text-xs text-gray-500 uppercase tracking-wider">Hash Function</div>
                </div>
                <div>
                  <div className="text-3xl font-bold text-yellow-400 mb-1">6D Chaos</div>
                  <div className="text-xs text-gray-500 uppercase tracking-wider">RNG System</div>
                </div>
              </div>
            </div>
          </>
        )}

        {view === 'register' && (
          <Registration
            onBack={() => setView('home')}
            onSuccess={() => {
              setView('login')
            }}
          />
        )}

        {view === 'login' && (
          <Login
            onBack={() => setView('home')}
            onSuccess={handleLoginSuccess}
          />
        )}

        {view === 'enroll' && enrollUserId && (
          <DeviceEnrollment
            userId={enrollUserId}
            onBack={() => {
              setEnrollUserId(null)
              setView('home')
            }}
            onEnrollmentComplete={(deviceId) => {
              setEnrollUserId(null)
              setView('hardware-login')
            }}
          />
        )}

        {/* Enroll Device Modal */}
        <EnrollDeviceModal
          isOpen={showEnrollModal}
          onClose={() => setShowEnrollModal(false)}
          onEnroll={(userId) => {
            setEnrollUserId(userId)
            setShowEnrollModal(false)
            setView('enroll')
          }}
        />

        {view === 'hardware-login' && (
          <Login
            onBack={() => setView('home')}
            onSuccess={handleLoginSuccess}
            hardwareMode={true}
          />
        )}
      </div>

      <footer className="mt-12 text-center text-gray-400 text-sm relative z-10">
        <div className="inline-block px-6 py-3 bg-gray-800 bg-opacity-30 backdrop-blur-md rounded-full border border-gray-700 border-opacity-30">
          <p className="font-medium">Built with zkSNARKs, TPM 2.0, and Modern Cryptography</p>
          <p className="mt-1 text-xs text-gray-500">BN254 Curve • Groth16 • TPM Attestation • Hardware Security</p>
        </div>
      </footer>
    </div>
  )
}

export default App

