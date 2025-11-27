# zkSNARK Hardware-Attested Authentication System

A production-grade authentication system combining **Zero-Knowledge Proofs (zkSNARKs)**, **TPM/TEE Hardware Attestation**, **Challenge-Response Protocol**, and **Cryptographic Commitments** for secure, passwordless authentication.

## 🌟 Key Features

- **🔐 Hardware-Backed Security**: TPM 2.0 / TEE attestation for device trust
- **🎯 Zero-Knowledge Authentication**: Prove password knowledge without revealing it
- **🔗 Device Binding**: Link authentication to specific hardware
- **🎲 Challenge-Response**: Nonce-based replay protection
- **📝 Audit Trail**: Complete transparency ledger for compliance
- **🔄 SRS Management**: Tracked zkSNARK trusted setup ceremonies
- **🚫 Revocation**: Instant device blocking capability
- **🌐 Modern Web UI**: React frontend with browser-based proof generation

## 🔐 How It Works

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     User Device (TPM 2.0)                   │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Password  │→│ Hash to Field │→│  Build Witness   │   │
│  └────────────┘  └──────────────┘  └──────────────────┘   │
│         ↓                                    ↓               │
│  ┌────────────────────────────────────────────────────┐    │
│  │  TPM: Sign(nonce || timestamp || SRS_ID)           │    │
│  │  Generate Attestation Quote (PCRs + Signature)     │    │
│  └────────────────────────────────────────────────────┘    │
│         ↓                                    ↓               │
│  ┌────────────────────────────────────────────────────┐    │
│  │  zkSNARK Prover: Generate π                        │    │
│  │  Prove: g0*X=Y AND attestation_valid               │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────┬───────────────────────────────────────┘
                      │ Send: {x, Attestation, π}
                      ↓
┌─────────────────────────────────────────────────────────────┐
│                      Server / Verifier                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 1. Verify SRS_ID                                    │   │
│  │ 2. Verify Attestation (Cert, PCRs, Signature)       │   │
│  │ 3. Check Timestamp Freshness                        │   │
│  │ 4. Verify zkSNARK Proof π                           │   │
│  │ 5. Check Device Not Revoked                         │   │
│  │ 6. Log to Audit Trail                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                ✓ Grant Access / ✗ Reject                    │
└─────────────────────────────────────────────────────────────┘
```

### Protocol Flow

#### 1. Device Enrollment (One-Time)
```
Client → Server: Enroll device
Server: Generate device key in TPM, issue certificate
Server: Record device in registry
Ledger: Log enrollment event
```

#### 2. User Registration (One-Time)
```
Client → Server: Request g0
Server → Client: g0 (random field element)
Client: Compute Y = g0 × Hash(password) mod p
Client → Server: {user_id, g0, Y}
Server: Store commitment (no password!)
```

#### 3. Authentication (Per-Session)
```
Client → Server: Request challenge
Server → Client: {N (nonce), t (timestamp), SRS_ID}

Client:
  - TPM: Sign(N || t || SRS_ID) → sig_dev
  - TPM: Read PCRs → device state
  - Create Attestation = {sig_dev, PCRs, certificate}
  - Hash password → X
  - Generate zkSNARK proof: g0 × X = Y
  
Client → Server: {Attestation, Proof π, Public signals}

Server:
  - Verify attestation certificate chain ✓
  - Verify TPM signature ✓
  - Check timestamp freshness ✓
  - Verify PCR policy ✓
  - Check device not revoked ✓
  - Verify zkSNARK proof ✓
  - Log to audit trail ✓
  
Server → Client: Access granted + session token
```

## 🛠️ Technology Stack

### Cryptography
- **Circom 2.0**: Circuit definition language
- **snarkjs**: zkSNARK proof generation/verification
- **Groth16**: Succinct zkSNARK proving system
- **BN254 Curve**: 254-bit pairing-friendly elliptic curve
- **Poseidon Hash**: ZK-friendly hash function

### Hardware Security
- **TPM 2.0**: Trusted Platform Module (Infineon, Intel, etc.)
- **tpm2-pytss**: Python TPM interface
- **Non-exportable keys**: Hardware-protected signing
- **PCR Attestation**: Platform integrity measurement

### Backend
- **Python 3.8+**: Core logic
- **FastAPI**: Modern async web framework
- **Uvicorn**: ASGI server
- **Pydantic**: Data validation

### Frontend
- **React 18**: UI framework
- **Vite**: Build tool
- **Tailwind CSS**: Styling
- **snarkjs (browser)**: Client-side proof generation

## 📋 Prerequisites

- **Python 3.8+**
- **Node.js 16+** and npm
- **Windows 10/11** with TPM 2.0 (or Linux with TPM support)
- **circom** (circuit compiler)
- **snarkjs** (proof toolkit)
- **PowerShell** (for Windows setup)

### Check Your TPM Status

```powershell
Get-Tpm
```

Expected output should show:
```
TpmPresent: True
TpmReady: True
TpmEnabled: True
```

## 🚀 Installation

### 1. Clone Repository
```bash
git clone <repository-url>
cd chaotic
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

This installs:
- FastAPI, Uvicorn (web server)
- cryptography (certificates, signing)
- pywin32 (Windows TPM interface via WMI)
- numpy (chaotic RNG)
- pycryptodome (crypto primitives)

### 3. Install zkSNARK Tools
```bash
# Install globally
npm install -g circom snarkjs
```

### 4. Install Frontend Dependencies
```bash
cd frontend
npm install
cd ..
```

### 5. Run zkSNARK Trusted Setup

**For original simple circuit:**
```powershell
pwsh scripts/setup_snark.ps1
```

**For hardware-attested circuit:**
```bash
# Compile enhanced circuit
circom circuits/auth_hardware.circom --r1cs --wasm --sym -o build/

# Powers of Tau (if not done yet)
snarkjs powersoftau new bn128 12 build/pot12_0000.ptau
snarkjs powersoftau contribute build/pot12_0000.ptau build/pot12_final.ptau --name="First contribution"

# Generate proving/verification keys
snarkjs groth16 setup build/auth_hardware.r1cs build/pot12_final.ptau keys/auth_hw_proving_key.zkey
snarkjs zkey export verificationkey keys/auth_hw_proving_key.zkey keys/auth_hw_verification_key.json

# Copy to static for web
cp build/auth_hardware.wasm static/
cp keys/auth_hw_proving_key.zkey static/
cp keys/auth_hw_verification_key.json static/
```

### 6. Start the Web Stack

```powershell
# Software/fallback mode (useful if no TPM)
pwsh start_web.ps1

# Real TPM mode (requires elevated PowerShell)
pwsh start_web.ps1 -Admin
```

> **Important:** When switching between software and real TPM modes, re-enroll each
> device so the stored certificate and signing material match the live TPM keys.

## ⚡ Quick Start - Automatic Device Enrollment!

**🎉 Device enrollment now happens AUTOMATICALLY when you register!**

### New Simplified Flow:
1. **Register** → Account created + Device auto-enrolled ✅
2. **Login** (simple) → Works immediately
3. **Hardware Login** → Extra secure with TPM attestation

**No manual device IDs needed - everything is automatic!**

---

## 🔑 Simple Login vs. Hardware Login

| Feature | Simple Login (default) | Hardware Login (enhanced) |
| --- | --- | --- |
| What is proved? | zkSNARK proves you know the password (g₀·X = Y) | Same zkSNARK proof **plus** digest of TPM attestation |
| Hardware binding | ❌ None – any browser with the password can log in | ✅ Device-bound via TPM certificate + PCR quote |
| Requirements | Browser + snarkjs (WASM) | Browser + snarkjs **and** TPM 2.0 (Windows pywin32 or Linux tpm2-pytss) |
| Replay protection | Challenge nonce embedded only in zk proof | Nonce checked by both TPM signature **and** zk proof |
| Enrollment data | Stores `g0`, `Y` commitment only | Stores commitment **and** TPM metadata (cert, PCR baseline, thumbprint/key handle) |
| Ideal use cases | Demos, CI tests, environments without TPM | Production laptops, kiosks, or any device you physically manage |

### When to use each mode?

1. **Simple Login**: quickest path to try the protocol. Use when TPM hardware is unavailable or when you just want passwordless proofs.
2. **Hardware Login**: use whenever you need device binding. Stolen credentials alone are useless because the server verifies the TPM quote and certificate match the enrolled device.

### Switching between modes

- UI: the landing screen shows both **“Login”** (simple) and **“Hardware Login”** cards. Pick the one you want per session.
- Backend: both flows run on the same FastAPI instance. Hardware endpoints (`/api/devices/*`, `/api/auth/*`) kick in automatically.
- Frontend: hardware mode fingerprints the browser (`device_<hash>`), auto-enrolls the current machine, then performs attestation + zkSNARK.

### Hardware login prerequisites

1. Start the stack with real TPM access:

   ```powershell
   # Elevated PowerShell
   pwsh start_web.ps1 -Admin
   ```

2. Ensure dependencies are installed (`pywin32` on Windows or `tpm2-pytss` on Linux).
3. Register the user (same as simple mode). The frontend immediately enrolls this device via `/api/devices/enroll`.
4. During login the frontend:
   - Requests a challenge `(nonce, timestamp, SRS_ID)`
   - Asks the local TPM to sign the challenge + PCR values
   - Builds the zkSNARK proof that ties password knowledge to the attestation digest
   - Sends `{attestation, proof, publicSignals}` to `/api/auth/verify`

If you choose the simple login, only the zkSNARK proof is generated and `/api/login` is called—no TPM interaction.

---

## 🔧 Windows TPM Access

**Your Infineon TPM 2.0 is accessed via `pywin32` (already installed).**

The system automatically uses real TPM when `pywin32` is available:
```powershell
# Just restart the server after installing dependencies
python api_server.py
```

Check console output:
- ✅ `[TPM] Successfully connected to Windows TPM 2.0` = Real TPM
- ⚠️ `[TPM] Using software fallback mode` = Software mode

**Note:** Windows TPM access uses WMI (Windows Management Instrumentation) - no admin needed!

---

## 💻 Usage

### Option 1: Hardware-Attested Web Interface (Production)

**Terminal 1 - Start Backend:**
```bash
python api_hardware_server.py
```

Server runs on `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/health`

**Terminal 2 - Start Frontend:**
```bash
cd frontend
npm run dev
```

Frontend runs on `http://localhost:5173`

Open browser to `http://localhost:5173` and:
1. **Enroll Device** - Register your device with TPM
2. **Register User** - Create account with commitment
3. **Login** - Authenticate with hardware attestation + zkSNARK

### Option 2: Simple Web Interface (Development)

Use original system without hardware attestation:

```bash
# Terminal 1
python api_server.py

# Terminal 2
cd frontend
npm run dev
```

### Option 3: CLI Interface

```bash
python main.py
```

Follow prompts to register and login.

## 📁 Project Structure

```
chaotic/
├── README.md                          # This file (ONLY documentation)
├── requirements.txt                   # Python dependencies
│
├── circuits/
│   ├── auth.circom                    # Simple circuit (g0*X=Y)
│   └── auth_hardware.circom           # Enhanced with attestation
│
├── hardware/                          # Hardware attestation
│   ├── __init__.py
│   ├── tpm_integration.py             # TPM 2.0 interface
│   ├── device_manager.py              # Device enrollment/revocation
│   └── attestation_verifier.py        # Attestation verification
│
├── srs/                               # Trusted setup management
│   ├── __init__.py
│   ├── srs_manager.py                 # SRS lifecycle
│   └── ledger.py                      # Transparency ledger
│
├── Core Python Files:
├── zkp_protocol.py                    # Simple ZKP protocol
├── zkp_hardware_protocol.py           # Hardware-attested protocol
├── api_server.py                      # Simple API
├── api_hardware_server.py             # Hardware-attested API
├── audit_logger.py                    # Security audit logging
├── chaotic_generator.py               # 6D hyper-chaotic RNG
├── hash_utils.py                      # Field arithmetic
├── zksnark_utils.py                   # Proof generation/verification
├── main.py                            # CLI interface
│
├── frontend/                          # React web interface
│   ├── src/
│   │   ├── components/
│   │   │   ├── Login.jsx
│   │   │   ├── Registration.jsx
│   │   │   └── Dashboard.jsx
│   │   └── utils/
│   │       ├── api.js
│   │       ├── crypto.js
│   │       └── snarkProof.js
│   ├── package.json
│   └── vite.config.js
│
├── keys/                              # zkSNARK keys
├── static/                            # Web-accessible artifacts
└── build/                             # Compiled circuits
```

## 🔬 API Endpoints

### Device Management
- `POST /api/devices/enroll` - Enroll new device
- `GET /api/devices/{device_id}` - Get device info
- `GET /api/devices` - List all devices
- `POST /api/devices/revoke` - Revoke device
- `GET /api/devices/user/{user_id}` - Get user's devices

### Authentication
- `POST /api/auth/challenge` - Request challenge
- `POST /api/auth/verify` - Verify attestation + proof
- `GET /api/register/g0` - Get random field element
- `POST /api/register` - Register user
- `GET /api/users/{user_id}/data` - Get user commitment

### Audit & Transparency
- `GET /api/audit/recent` - Recent audit entries
- `GET /api/audit/user/{user_id}` - User history
- `GET /api/audit/device/{device_id}` - Device history
- `GET /api/audit/verify` - Verify ledger integrity

### System
- `GET /api/health` - System status
- `GET /api/srs` - List SRS ceremonies

Full interactive docs: `http://localhost:8000/docs`

## 🧪 Testing

### 1. Test TPM Status
```powershell
Get-Tpm
```

### 2. Test Device Enrollment
```bash
curl -X POST http://localhost:8000/api/devices/enroll \
  -H "Content-Type: application/json" \
  -d '{"device_id": "device001", "user_id": "alice"}'
```

### 3. Test Registration
```bash
# Get g0
curl http://localhost:8000/api/register/g0

# Register (use returned g0)
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "g0": "12345", "Y": "67890"}'
```

### 4. Test Challenge-Response
```bash
# Request challenge
curl -X POST http://localhost:8000/api/auth/challenge \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "device_id": "device001"}'

# Use web UI or CLI to complete authentication
```

### 5. Check Audit Trail
```bash
curl http://localhost:8000/api/audit/recent
```

### 6. Verify Ledger Integrity
```bash
curl http://localhost:8000/api/audit/verify
```

## 🔒 Security Properties

### ✅ Protections

| Threat | Mitigation |
|--------|-----------|
| **Password Exposure** | Password never transmitted or stored |
| **Server Compromise** | Only commitments stored (not passwords) |
| **Replay Attacks** | Nonce + timestamp in challenge |
| **Device Spoofing** | TPM attestation with hardware keys |
| **Stolen Credentials** | Requires both password AND enrolled device |
| **Man-in-the-Middle** | Cryptographic proofs cannot be forged |
| **Brute Force** | Field-sized search space (2^254) |
| **Session Hijacking** | Fresh proof required per session |

### 🛡️ Audit & Compliance

- **Transparency Ledger**: Append-only log of all events
- **Audit Logging**: Detailed logs for forensic analysis
- **Device Revocation**: Instant blocking capability
- **PCR Tracking**: Platform integrity monitoring
- **SRS Provenance**: Ceremony participant tracking

### ⚠️ Limitations

- **Trusted Setup**: SRS ceremony must be performed honestly
- **Weak Passwords**: System allows weak passwords (add strength checks)
- **Client Security**: Device must be trusted for password input
- **Quantum**: Not post-quantum secure (BN254 vulnerable to quantum)
- **TPM Limitations**: Software fallback if no TPM available

## 📊 Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Device Enrollment | < 1s | One-time per device |
| User Registration | < 500ms | One-time per user |
| Challenge Generation | < 50ms | Per authentication |
| TPM Attestation | < 200ms | Per authentication |
| zkSNARK Proof (Browser) | 10-30s | Varies by CPU |
| zkSNARK Proof (Server) | 5-15s | Faster than browser |
| Proof Verification | < 100ms | Fast verification |
| Attestation Verification | < 100ms | Includes cert check |

**Artifact Sizes:**
- `auth_hardware.wasm`: ~800 KB
- `auth_hw_proving_key.zkey`: ~8-12 MB
- `auth_hw_verification_key.json`: ~2 KB

## 🔧 Configuration

### TPM Mode

The system automatically detects TPM availability:
- **Hardware Mode**: Uses real TPM 2.0 chip
- **Software Mode**: Cryptographic fallback for development

Force software mode for testing:
```python
# In hardware/tpm_integration.py
TPM_AVAILABLE = False  # Set manually
```

### PCR Policy

Configure which PCRs are checked:
```python
# In hardware/attestation_verifier.py
self.required_pcr_indices = [0, 1, 2, 3, 7]  # Boot integrity
```

### Timestamp Freshness

Configure replay protection window:
```python
# In hardware/attestation_verifier.py
self.max_timestamp_skew = 300  # 5 minutes
```

## 🐛 Troubleshooting

### TPM Not Found

**Problem:** `TpmPresent: False`

**Solutions:**
1. Check BIOS/UEFI settings - enable TPM
2. Update TPM firmware
3. Install TPM drivers
4. System will fallback to software mode

### Proof Generation Slow

**Problem:** Taking > 60 seconds

**Solutions:**
1. Use smaller circuit (auth.circom instead of auth_hardware.circom)
2. Reduce constraint count
3. Use server-side proof generation
4. Upgrade CPU (proof generation is CPU-intensive)

### Certificate Errors

**Problem:** "Certificate chain verification failed"

**Solutions:**
1. In dev mode, using self-signed certs is OK
2. For production, get proper CA-issued certificates
3. Check certificate expiration dates

### Port Already in Use

**Problem:** "Port 8000 already in use"

**Solutions:**
```bash
# Find process
netstat -ano | findstr :8000

# Kill process (Windows)
taskkill /PID <pid> /F

# Or use different port
python api_hardware_server.py --port 8001
```

## 🚀 Production Deployment

### Backend (Gunicorn)
```bash
gunicorn api_hardware_server:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile access.log \
  --error-logfile error.log
```

### Frontend (Build)
```bash
cd frontend
npm run build
# Serve dist/ with nginx
```

### Database (Production Enhancement)

Replace in-memory storage:
```python
# Use PostgreSQL for persistence
# Use Redis for sessions
# Use distributed key-value store
```

### Monitoring

- **Prometheus** for metrics
- **Grafana** for dashboards
- **ELK Stack** for log aggregation
- Monitor proof generation times
- Track failed authentication attempts

## 📚 References

- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [Circom Documentation](https://docs.circom.io/)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [snarkjs GitHub](https://github.com/iden3/snarkjs)
- [Zero-Knowledge Proofs](https://zkp.science/)

## 📄 License

Educational and research use. Review thoroughly before production deployment.

## 🙏 Acknowledgments

- Circom and snarkjs teams
- TPM Working Group
- Cryptography research community
- BN254 curve designers

---

**⚠️ Security Notice:** This system demonstrates hardware-attested zkSNARK authentication. For production use:
1. Conduct security audit
2. Use MPC for trusted setup
3. Implement rate limiting
4. Add password strength requirements
5. Deploy with HTTPS/TLS
6. Regular security updates

**Built with zkSNARKs + TPM 2.0 + Zero-Knowledge Cryptography** 🔐✨
