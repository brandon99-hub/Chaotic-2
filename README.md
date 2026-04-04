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

## 🎓 Understanding the System

### What is zkSNARK Authentication?

**zkSNARK** = Zero-Knowledge Succinct Non-Interactive Argument of Knowledge

In simple terms: **Prove you know something without revealing what you know.**

#### Traditional Login (Insecure):
```
You → Server: "My password is MySecretPass123"
Server: Checks if it matches stored hash
Problem: Password travels over network, server stores hash
```

#### zkSNARK Login (Secure):
```
You → Server: "Here's a proof I know the password"
Server: Verifies proof mathematically
Benefit: Password NEVER leaves your device, server NEVER sees it!
```

### The Three Phases Explained

#### Phase 1: Trusted Setup (ONE TIME - Before Deployment)

**What happens:**
- Multiple independent people (participants) contribute randomness
- Creates two keys: Proving Key and Verification Key
- Secret parameters (called "toxic waste") are generated and DESTROYED

**Who's involved:** 3-5+ independent participants (real people/organizations)

**When:** Once, before the system goes live

**Output:**
- `auth_proving_key.zkey` (8-12 MB) - Used to create proofs
- `auth_verification_key.json` (2 KB) - Used to verify proofs

**Why multiple participants?**

If ONE person runs the setup alone, they could forge proofs for ANY user! With multiple participants, as long as ONE is honest and destroys their secret, the system is secure.

```
Security Guarantee: 1 honest participant out of N = System is secure!

Example:
- 5 participants total
- 4 are malicious and keep their secrets
- 1 is honest and destroys their secret
- Result: System is STILL SECURE! ✓
```

**Real-world examples:**
- Zcash: 200+ participants
- Ethereum: 1000+ participants  
- Hermez: 300+ participants

#### Phase 2: User Registration (Once Per User)

**What happens:**
1. Server generates random number `g0`
2. User enters password → hashed to `X`
3. User computes commitment: `Y = g0 × X`
4. User sends `{g0, Y}` to server (NOT the password!)
5. Server stores commitment

**What's stored on server:**
```python
users["alice"] = {
    "g0": "random_field_element",
    "Y": "commitment"
}
# ❌ Password is NEVER stored
# ❌ Password hash is NEVER stored
```

**Why this is secure:**
- Given `g0` and `Y`, it's mathematically impossible to compute `X` (the password)
- This is the Discrete Logarithm Problem - computationally infeasible!

**Hardware Mode Addition:**
- Device is auto-enrolled during registration
- TPM generates non-exportable key (welded to the chip)
- PCR baseline captured (system state snapshot)

#### Phase 3: Login (Every Time)

**What happens:**
1. User enters password → hashed to `X`
2. User generates zkSNARK proof: "I know X such that g0 × X = Y"
3. User sends proof to server (NOT the password!)
4. Server verifies proof
5. If valid → Access granted!

**Hardware Mode Addition:**
1. Server sends challenge (nonce + timestamp)
2. TPM signs challenge with hardware-protected key
3. TPM includes PCR measurements (system state)
4. Server verifies:
   - TPM signature (proves it's Alice's device)
   - PCRs match baseline (proves system not tampered)
   - zkSNARK proof (proves password knowledge)
   - Nonce matches (prevents replay attacks)

### Understanding the Keys

#### Proving Key (8-12 MB)
- **Purpose:** Create proofs
- **Used by:** User's browser during login
- **Analogy:** A puzzle maker that creates mathematical puzzles
- **Created:** Once during trusted setup
- **Reused:** For ALL users, ALL logins, FOREVER

#### Verification Key (2 KB)
- **Purpose:** Check proofs
- **Used by:** Server during login
- **Analogy:** A puzzle checker that validates solutions
- **Created:** Once during trusted setup
- **Reused:** For ALL users, ALL logins, FOREVER

**Think of it like:** Installing software once (trusted setup) and using it forever (registration + login).

### Understanding Hardware Attestation

#### What is TPM?
**TPM** = Trusted Platform Module - A security chip built into your computer.

```
Your Computer:
┌─────────────────────────────────────┐
│  CPU, RAM, Hard Drive               │
│                                     │
│  ┌─────────────────────────────┐   │
│  │  TPM Chip                   │   │
│  │  • Stores secret keys       │   │
│  │  • Signs data               │   │
│  │  • Keys CANNOT be exported  │   │
│  │  • Measures system state    │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

**Key feature:** Private keys are "welded" to the chip - cannot be copied or exported!

#### What are PCRs?
**PCRs** = Platform Configuration Registers - Snapshots of system components.

During boot, TPM measures:
- PCR 0: BIOS firmware
- PCR 1: BIOS configuration
- PCR 7: Secure Boot state

**Why this matters:** If malware infects the BIOS, the PCR values change and login is BLOCKED!

```
Clean System:
PCR 0: a1b2c3d4e5f6...  ✓

Hacked System (malware in BIOS):
PCR 0: XXXXXXXXXX...  ✗ Different! Login BLOCKED!
```

#### What is Attestation?
**Attestation** = Proof of Identity + Proof of State

```
Attestation Package:
┌─────────────────────────────────────┐
│ 1. Certificate (Proof of Identity) │
│    "This is Alice's laptop"         │
│                                     │
│ 2. PCRs (Proof of State)            │
│    "System hasn't been tampered"    │
│                                     │
│ 3. Signature (Proof of Authenticity)│
│    "This came from Alice's TPM"     │
│                                     │
│ 4. Nonce (Proof of Freshness)       │
│    "This is a fresh response"       │
└─────────────────────────────────────┘
```

#### What is a Nonce?
**Nonce** = Number used ONCE - Prevents replay attacks.

```
Without Nonce (VULNERABLE):
Day 1: Alice logs in → Attestation sent
       Hacker records attestation
Day 2: Hacker replays old attestation
       Server accepts it ✗ PROBLEM!

With Nonce (SECURE):
Day 1: Server sends nonce 12345
       Alice's TPM signs with nonce 12345
Day 2: Server sends nonce 67890
       Hacker tries old attestation (nonce 12345)
       Server rejects it ✓ BLOCKED!
```

### Security Model

#### What Each Component Prevents

| Component | Prevents |
|-----------|----------|
| **zkSNARK Proof** | Password exposure (password never sent) |
| **Commitment** | Server compromise (only commitment stored) |
| **Nonce** | Replay attacks (old proofs rejected) |
| **Timestamp** | Time-based attacks (expired challenges rejected) |
| **TPM Signature** | Device spoofing (only Alice's TPM can sign) |
| **PCRs** | Malware (system tampering detected) |
| **Certificate** | Device substitution (different laptop blocked) |
| **Multiple Participants** | Insider attacks (no single person can forge proofs) |

#### Attack Scenarios

**Attack 1: Hacker Steals Password**

Simple Mode:
```
Hacker steals password ✓
Hacker generates zkSNARK proof ✓
Hacker logs in successfully ✓  ← 😱 PROBLEM!
```

Hardware Mode:
```
Hacker steals password ✓
Hacker tries to generate attestation...
Server: "Show me your TPM signature"
Hacker: "I don't have Alice's TPM!"
Server: "Login denied" ✗  ← ✅ BLOCKED!
```

**Attack 2: Replay Attack**
```
Hacker records Alice's login ✓
Next day, hacker replays it...
Server: "Wrong nonce! Expected 67890, got 12345"
Login denied ✗  ← ✅ BLOCKED!
```

**Attack 3: BIOS Malware**
```
Hacker infects Alice's BIOS with malware ✓
Alice tries to login...
TPM reads PCRs: DIFFERENT from baseline!
Server: "System has been tampered with"
Login denied ✗  ← ✅ BLOCKED!
```

**Attack 4: Server Compromise**
```
Hacker hacks server ✓
Hacker gets: {g0, Y} commitments
Hacker tries to compute password...
Math: X = Y / g0 (Discrete Log Problem)
Result: COMPUTATIONALLY INFEASIBLE ✗
Passwords remain safe ✓
```

### Password Flow

#### Where the Password is Used

**Registration:**
```
Password: "MySecretPass123"
    ↓ Hash
X = SHA256("MySecretPass123") = 789012345...
    ↓ Multiply by g0
Y = g0 × X = 123456789...
    ↓ Send to server
Server stores: {g0, Y}
```

**Login:**
```
Password: "MySecretPass123"
    ↓ Hash
X = SHA256("MySecretPass123") = 789012345...
    ↓ Generate proof
Proof = "I know X such that g0 × X = Y"
    ↓ Send to server
Server verifies proof
```

**What is NEVER Stored:**
- ❌ Password ("MySecretPass123")
- ❌ Password hash (X = 789012345...)
- ✅ Commitment (Y = g0 × X) ← This is stored
- ✅ Random g0 ← This is stored

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

> **⚠️ IMPORTANT:** The trusted setup is a critical security component. For production, you MUST use a Multi-Party Computation (MPC) ceremony with multiple independent participants.

#### Understanding Trusted Setup

The trusted setup creates two keys:
- **Proving Key** - Used by clients to create proofs
- **Verification Key** - Used by server to verify proofs

**Security:** If the secret parameters ("toxic waste") are not destroyed, someone could forge proofs for ANY user!

#### Option 1: Development Setup (Current - Single Participant)

**For testing only! NOT for production!**

```powershell
# Simple circuit
pwsh scripts/setup_snark.ps1
```

**For hardware-attested circuit:**
```bash
# Compile circuit
circom circuits/auth_hardware.circom --r1cs --wasm --sym -o build/

# Powers of Tau (Phase 1)
snarkjs powersoftau new bn128 12 build/pot12_0000.ptau
snarkjs powersoftau contribute build/pot12_0000.ptau build/pot12_final.ptau \
  --name="Development" --entropy="$(openssl rand -base64 32)"

# Prepare Phase 2
snarkjs powersoftau prepare phase2 build/pot12_final.ptau build/pot12_ready.ptau

# Circuit-specific setup (Phase 2)
snarkjs groth16 setup build/auth_hardware.r1cs build/pot12_ready.ptau \
  keys/auth_hw_proving_key.zkey

# Export verification key
snarkjs zkey export verificationkey keys/auth_hw_proving_key.zkey \
  keys/auth_hw_verification_key.json

# Copy to static for web
cp build/auth_hardware_js/auth_hardware.wasm static/
cp keys/auth_hw_proving_key.zkey static/
```

**Status:** Your `srs_registry.json` will show:
```json
{
  "participants": [],  // ⚠️ Zero participants - development only!
  "ceremony_transcript": "Development SRS - Not for production"
}
```

#### Option 2: Use Existing Trusted Setup (Recommended for Production)

Use a community-trusted Powers of Tau ceremony:

```bash
# Download Hermez's Powers of Tau (300+ participants)
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_15.ptau \
  -O build/powersOfTau_production.ptau

# Compile your circuit
circom circuits/auth_hardware.circom --r1cs --wasm --sym -o build/

# Setup with trusted Powers of Tau
snarkjs groth16 setup build/auth_hardware.r1cs \
  build/powersOfTau_production.ptau \
  keys/prod_proving_key.zkey

# Add your own contribution (optional but recommended)
snarkjs zkey contribute keys/prod_proving_key.zkey keys/prod_final.zkey \
  --name="YourOrganization" --entropy="$(openssl rand -base64 32)"

# Export verification key
snarkjs zkey export verificationkey keys/prod_final.zkey \
  keys/prod_verification_key.json
```

**Update your SRS registry:**
```python
# In your code
srs_manager.register_srs(
    srs_id="hermez_production_v1",
    ceremony_transcript="Hermez zkRollup Powers of Tau ceremony",
    participants=["Hermez Community (300+ participants)"],
    proving_key_path="keys/prod_final.zkey",
    verification_key_path="keys/prod_verification_key.json"
)
```

#### Option 3: Run Your Own MPC Ceremony (Maximum Security)

For maximum trust, coordinate your own Multi-Party Computation ceremony:

**Step 1: Find Participants (3-5+ independent people/organizations)**
- Your company's security team
- External security auditor
- Independent cryptographer
- Regulatory compliance officer
- Open-source community member

**Step 2: Coordinator starts the ceremony**
```bash
snarkjs powersoftau new bn128 12 pot_0000.ptau
# Send pot_0000.ptau to Participant 1
```

**Step 3: Each participant contributes**
```bash
# Participant 1
snarkjs powersoftau contribute pot_0000.ptau pot_0001.ptau \
  --name="SecurityTeam-Alice" --entropy="$(openssl rand -base64 32)"
# Participant 1 DELETES all files and sends pot_0001.ptau to Participant 2

# Participant 2
snarkjs powersoftau contribute pot_0001.ptau pot_0002.ptau \
  --name="Auditor-Bob" --entropy="$(openssl rand -base64 32)"
# Participant 2 DELETES all files and sends pot_0002.ptau to Participant 3

# ... repeat for all participants ...
```

**Step 4: Coordinator finalizes**
```bash
snarkjs powersoftau prepare phase2 pot_final.ptau pot_ready.ptau
snarkjs groth16 setup auth_hardware.r1cs pot_ready.ptau auth.zkey
snarkjs zkey export verificationkey auth.zkey verification_key.json
```

**Step 5: Document the ceremony**
```python
srs_manager.register_srs(
    srs_id="production_mpc_v1",
    ceremony_transcript="MPC ceremony conducted December 2024",
    participants=[
        "SecurityTeam-Alice",
        "Auditor-Bob",
        "Crypto-Charlie",
        "Compliance-David",
        "Community-Eve"
    ],
    proving_key_path="keys/auth_proving_key.zkey",
    verification_key_path="keys/auth_verification_key.json",
    attestation_hashes=[
        "sha256_of_pot_0001.ptau",
        "sha256_of_pot_0002.ptau",
        "sha256_of_pot_0003.ptau",
        "sha256_of_pot_0004.ptau",
        "sha256_of_pot_0005.ptau"
    ]
)
```

**Security Guarantee:** As long as ONE participant is honest and destroys their secret, the system is secure!

### 6. Copy Circuit Artifacts to Frontend
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

## ❓ Frequently Asked Questions (FAQ)

### General Questions

**Q: What makes this different from traditional password authentication?**

A: Traditional systems send your password (or hash) to the server. This system uses zkSNARKs to prove you know the password WITHOUT ever sending it. The server only stores a mathematical commitment, not your password.

**Q: Can I use this without a TPM chip?**

A: Yes! The system has two modes:
- **Simple Mode**: zkSNARK authentication only (works on any device)
- **Hardware Mode**: zkSNARK + TPM attestation (requires TPM 2.0)

The system automatically falls back to software mode if no TPM is detected.

**Q: Is this production-ready?**

A: The code is production-quality, but you need to:
1. Run a proper MPC trusted setup (or use Hermez's)
2. Replace in-memory storage with a database
3. Add rate limiting and HTTPS
4. Conduct a security audit

### Trusted Setup Questions

**Q: Why do I need multiple participants for trusted setup?**

A: If one person runs the setup alone, they could forge proofs for ANY user. With multiple participants, as long as ONE is honest and destroys their secret, the system is secure. It's called the "1-of-N" security model.

**Q: Can I just add fake names to the participants list?**

A: No! Participants must be REAL PEOPLE who actually run the ceremony commands on their own computers. Fake names provide zero security.

**Q: What happens if all participants are malicious?**

A: If ALL participants keep their secrets, they could collaborate to forge proofs. That's why you need independent participants from different organizations who don't trust each other.

**Q: Can I use the development setup for production?**

A: **NO!** The development setup has zero participants (just you). You know the secrets, so you could forge proofs. Always use Option 2 (Hermez) or Option 3 (your own MPC) for production.

**Q: How do I verify a trusted setup was done correctly?**

A: Each participant should publish a hash of their contribution. You can verify the chain of contributions matches the published hashes. Tools like `snarkjs` have built-in verification commands.

### Hardware Attestation Questions

**Q: What if my TPM is compromised?**

A: If an attacker gains control of your TPM, they could sign attestations. However:
1. TPM keys are hardware-protected and very difficult to extract
2. PCR measurements would detect system tampering
3. You can revoke the device from the server side

**Q: Why do you check PCRs?**

A: PCRs detect if malware infected your BIOS or bootloader. If the PCR values change from the baseline, login is blocked. This prevents "evil maid" attacks where someone physically modifies your device.

**Q: What if I update my BIOS?**

A: Legitimate BIOS updates will change PCR values. You'll need to re-enroll your device to capture the new PCR baseline. This is intentional - it forces verification after system changes.

**Q: Can I use this on mobile devices?**

A: The current implementation uses TPM 2.0 (desktop/laptop). For mobile:
- iOS: Use Secure Enclave (requires code changes)
- Android: Use TEE/StrongBox (requires code changes)

The zkSNARK part works on mobile browsers already!

### Security Questions

**Q: What if the server is hacked?**

A: The attacker gets commitments `{g0, Y}` but cannot compute passwords. The Discrete Logarithm Problem makes this computationally infeasible. Your passwords remain safe!

**Q: Can someone replay my login?**

A: No. Each login uses a fresh nonce (random number used once). Old proofs/attestations are rejected.

**Q: What if someone steals my password?**

A: 
- **Simple Mode**: They can login (same as traditional systems)
- **Hardware Mode**: They CANNOT login without your physical device (TPM)

Hardware mode provides defense-in-depth!

**Q: Is this quantum-resistant?**

A: No. The BN254 curve is vulnerable to quantum attacks. For post-quantum security, you'd need to:
1. Use a quantum-resistant zkSNARK system (e.g., STARKs)
2. Replace TPM RSA signatures with post-quantum signatures

**Q: What's the performance impact?**

A: 
- Proof generation: 10-30 seconds (browser), 5-15 seconds (server)
- Proof verification: <100ms
- TPM attestation: <200ms

The main bottleneck is client-side proof generation.

### Implementation Questions

**Q: Why is the proving key so large (8-12 MB)?**

A: It contains encrypted mathematical formulas for the entire circuit. The verification key is only 2 KB because it only needs to check, not create.

**Q: Can I reduce proof generation time?**

A: Yes:
1. Use a smaller circuit (fewer constraints)
2. Generate proofs on the server (but user must send password hash - less secure)
3. Use GPU acceleration (experimental)
4. Use PLONK instead of Groth16 (different tradeoffs)

**Q: Why use Poseidon hash instead of SHA-256 in the circuit?**

A: Poseidon is "ZK-friendly" - much more efficient in zkSNARK circuits. SHA-256 would require 10-100x more constraints, making proofs much slower.

**Q: Can I add biometric authentication?**

A: Yes! You could:
1. Hash fingerprint → use as password
2. Add biometric data to the witness
3. Prove "I have fingerprint X AND device Y"

The circuit would need modification.

**Q: How do I revoke a device?**

A: Call the revocation API:
```python
POST /api/devices/revoke
{
    "device_id": "device_abc123",
    "reason": "Device lost/stolen"
}
```

The device status changes to "revoked" and all future logins are blocked.

### Deployment Questions

**Q: What database should I use for production?**

A: Recommended:
- **PostgreSQL**: For user/device data
- **Redis**: For session management and active challenges
- **MongoDB**: Alternative for document-based storage

Replace the in-memory `self.users` and `self.devices` dictionaries.

**Q: How do I handle multiple servers?**

A: 
1. Store challenges in Redis (shared across servers)
2. Use database for user/device data
3. Load proving/verification keys on startup
4. Use load balancer with sticky sessions (optional)

**Q: What about rate limiting?**

A: Add rate limiting to prevent brute force:
```python
# Example with FastAPI
from slowapi import Limiter

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/login")
@limiter.limit("5/minute")  # 5 attempts per minute
async def login(request: Request):
    ...
```

**Q: How do I monitor the system?**

A: Key metrics to track:
- Proof generation time (client-side)
- Proof verification time (server-side)
- Failed authentication attempts
- Device enrollment rate
- TPM attestation failures
- PCR policy violations

Use Prometheus + Grafana for visualization.

### Troubleshooting

**Q: "snarkjs: command not found"**

A: Install snarkjs globally:
```bash
npm install -g snarkjs
```

**Q: "TPM not available" error**

A: Check TPM status:
```powershell
Get-Tpm
```

If TPM is disabled, enable it in BIOS. The system will fall back to software mode automatically.

**Q: Proof generation fails in browser**

A: Check:
1. WASM file is accessible: `static/auth_hardware.wasm`
2. Proving key is accessible: `static/auth_hw_proving_key.zkey`
3. Browser console for errors
4. File size limits (proving key is 8-12 MB)

**Q: "Invalid proof" error**

A: Common causes:
1. Wrong password entered
2. Proving/verification keys mismatch
3. Different SRS used for proof vs verification
4. Circuit was recompiled but keys weren't regenerated

**Q: PCR verification fails**

A: This means system state changed:
1. BIOS update → Re-enroll device
2. Secure Boot disabled → Re-enable or re-enroll
3. Malware detected → Investigate!

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
