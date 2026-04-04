const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8088'

export const api = {
  async getG0() {
    const response = await fetch(`${API_BASE_URL}/api/register/g0`)
    if (!response.ok) {
      throw new Error('Failed to get g0 from server')
    }
    return await response.json()
  },

  async register(hrId, Y, g0) {
    const response = await fetch(`${API_BASE_URL}/api/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        hr_id: hrId,
        Y: Y,
        g0: g0,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Registration failed')
    }
    
    return await response.json()
  },

  async getUserData(hrId) {
    const response = await fetch(`${API_BASE_URL}/api/users/${hrId}/data`)
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'User not found')
    }
    return await response.json()
  },

  async login(hrId, proof, publicSignals) {
    const response = await fetch(`${API_BASE_URL}/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        hr_id: hrId,
        proof: proof,
        public_signals: publicSignals,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Authentication failed')
    }
    
    return await response.json()
  },

  async healthCheck() {
    const response = await fetch(`${API_BASE_URL}/api/health`)
    return await response.json()
  },

  // ============ Hardware-Attested Auth API ============

  async enrollDevice(deviceId, userId) {
    const response = await fetch(`${API_BASE_URL}/api/devices/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        device_id: deviceId,
        user_id: userId,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Device enrollment failed')
    }
    
    return await response.json()
  },

  async generateDeviceAttestation(userId, deviceId, nonce, timestamp, srsId) {
    const response = await fetch(`${API_BASE_URL}/api/devices/attest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        user_id: userId,
        device_id: deviceId,
        nonce: nonce,
        timestamp: timestamp,
        srs_id: srsId,
      }),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Failed to generate attestation')
    }

    return await response.json()
  },

  async getDeviceInfo(deviceId) {
    const response = await fetch(`${API_BASE_URL}/api/devices/${deviceId}`)
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Device not found')
    }
    return await response.json()
  },

  async getUserDevices(userId) {
    const response = await fetch(`${API_BASE_URL}/api/devices/user/${userId}`)
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Failed to get devices')
    }
    return await response.json()
  },

  async revokeDevice(deviceId, reason) {
    const response = await fetch(`${API_BASE_URL}/api/devices/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        device_id: deviceId,
        reason: reason,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Device revocation failed')
    }
    
    return await response.json()
  },

  async requestChallenge(userId, deviceId) {
    const response = await fetch(`${API_BASE_URL}/api/auth/challenge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        user_id: userId,
        device_id: deviceId,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Challenge request failed')
    }
    
    return await response.json()
  },

  async verifyAuthentication(userId, deviceId, nonce, attestation, proof, publicSignals) {
    const response = await fetch(`${API_BASE_URL}/api/auth/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        user_id: userId,
        device_id: deviceId,
        nonce: nonce,
        attestation: attestation,
        proof: proof,
        public_signals: publicSignals,
      }),
    })
    
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Authentication verification failed')
    }
    
    return await response.json()
  },

  async getAuditHistory(userId, limit = 50) {
    const response = await fetch(`${API_BASE_URL}/api/audit/user/${userId}?limit=${limit}`)
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Failed to get audit history')
    }
    return await response.json()
  },

  async getSRSList() {
    const response = await fetch(`${API_BASE_URL}/api/srs`)
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.detail || 'Failed to get SRS list')
    }
    return await response.json()
  },
}

