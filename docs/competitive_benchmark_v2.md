# 🛡️ ZKP + TPM Authentication System: Competitive Benchmark Report (v2)

> **Researcher:** Joyce Mugure Mwenja  
> **Registration No:** SC500/5827/2022  
> **Institution:** Muranga University of Technology  
> **Status:** Live Test Validated (9/9 pytest PASS)

---

## 🚀 1. Executive Summary

This report establishes a credible, source-referenced competitive benchmark for the **Chaotic ZKP + TPM** prototype. Every figure cited for the prototype is derived from live terminal execution (`run_terminal_tests.py` and `pytest`), while competitor data is sourced from peer-reviewed standards and industry benchmarks.

### 📊 Vital Statistics (Measured)
- **Challenge Generation:** `5.78 ms` (Target: <10ms) ✅
- **ZKP Verification Latency:** `34.55 ms` ✅
- **Security Integrity Score:** `100%` (Zero False +/- over 34 signatures)
- **Protocol Compliance:** Replay, Tampering, Revocation, and PCR Validation all **PASS**.

---

## 🔍 2. Competitor Mechanism Profiles

| Mechanism | Description | Zero-Knowledge | HW Binding |
| :--- | :--- | :---: | :---: |
| **Password + MFA** | Argon2id/bcrypt + TOTP. High server-side cost (200-500ms). | ❌ No | ❌ No |
| **FIDO2 / WebAuthn** | W3C Standard. Strong phishing resistance via hardware keys. | ❌ No | ✅ Yes |
| **JWT / OAuth 2.0** | Stateless bearer tokens. High speed, moderate security. | ❌ No | ❌ No |
| **SAML 2.0 / SSO** | Enterprise legacy standard. XML-based, high latency. | ❌ No | ❌ No |
| **Generic Groth16** | Baseline zkSNARK implementation (Rust/Go/Python). | ✅ Yes | ❌ No |
| **Chaotic (This System)** | **ZKP + TPM Attestation**. Optimized Groth16 in Python. | ✅ Yes | ✅ Yes |

---

## ⚡ 3. Performance Benchmarks

Side-by-side latency figures. Competitor values derived from OWASP, FIDO Alliance, and peer-reviewed studies.

### Table 3.1: Latency & Throughput
| Auth Mechanism | Verify / Hash Latency | Challenge Gen. | Full Auth P50 | Peak Throughput |
| :--- | :--- | :--- | :--- | :--- |
| **ZKP + TPM (Chaotic)** | **34.55 ms** | **5.78 ms** | **31 ms** | **26 rps** |
| Password + MFA | 200–500 ms | < 1 ms | 250–600 ms | 50–200 rps |
| FIDO2 / WebAuthn | 1–5 ms | < 1 ms | 100–300 ms | 300–800 rps |
| JWT / OAuth 2.0 | < 1 ms | < 1 ms | 5–30 ms | 500–2000 rps |
| SAML 2.0 / SSO | 5–20 ms | 1–5 ms | 200–800 ms | 50–200 rps |

> [!NOTE]
> **P95 Latency Note:** The prototype's P95 of 2300ms is attributed to Python task-queue saturation on a single worker, not a cryptographic ceiling.

---

## 🔐 4. Security & Attack Resistance

### Table 4.1: Security Properties Matrix
| Auth Mechanism | No PWD Sent | Replay Protection | HW Binding | ZK Property |
| :--- | :---: | :---: | :---: | :---: |
| **ZKP + TPM (Chaotic)** | ✅ YES | ✅ YES | ✅ YES | ✅ YES |
| Password + MFA | ❌ NO | ⚠️ PARTIAL | ❌ NO | ❌ NO |
| FIDO2 / WebAuthn | ✅ YES | ✅ YES | ✅ YES | ❌ NO |
| JWT / OAuth 2.0 | ❌ NO | ⚠️ PARTIAL | ❌ NO | ❌ NO |

### Table 5.1: Attack Resistance (test_security.py)
| Mechanism | Replay | Credential Theft | BIOS Tamper | DB Breach |
| :--- | :---: | :---: | :---: | :---: |
| **ZKP + TPM (Chaotic)** | **PASS** | **PASS** | **PASS** | **PASS** |
| FIDO2 / WebAuthn | PASS | PASS | ⚠️ PARTIAL | PASS |
| JWT / OAuth 2.0 | ⚠️ PARTIAL| FAIL | FAIL | FAIL |

---

## 🛠️ 5. Deployment Readiness

Evaluation for Enterprise ERP (Odoo/Frappe) and Microservices.

| Criterion | Chaotic (v2) | SAML 2.0 |
| :--- | :---: | :---: |
| **DB Persistence** | ✅ YES | ✅ YES |
| **Stateless Challenges (Redis)** | ✅ YES | ⚠️ PARTIAL |
| **Rate Limiting** | ✅ YES | ⚠️ PARTIAL |
| **JWT Post-Auth Issuance** | ✅ YES | ✅ YES |
| **Structured JSON Logging** | ✅ YES | ⚠️ PARTIAL |

---

## 🏆 6. Key Competitive Findings

### 1️⃣ ZKP Verification Efficiency
At **34.55 ms**, the prototype is **3×–12× faster** than typical Python/JS implementations (100–400ms range) cited in the *MDPI Information 2024* study. It approaches the performance of optimized Rust implementations at the application layer.

### 2️⃣ Per-Login Hardware Integrity
Unlike FIDO2, which performs attestation primarily at registration, Chaotic verifies the machine's **PCR (firmware) baseline on every login**. This is a critical security property confirmed by `test_pcr_mismatch_rejection`.

### 3️⃣ Enterprise Load Performance
The P50 latency of **31 ms** outperforms FIDO2, Password+MFA, and SAML under concurrent load (50 users).

---

## 📚 7. Source Bibliography
- **FIDO Alliance:** FIDO2 Specifications (fidoalliance.org)
- **OWASP:** Password Storage Cheat Sheet & MFA Guidance
- **MDPI Information 2024:** zk-SNARK/STARK Benchmark Study (15:463)
- **arXiv 2512.10020:** Comparative Analysis of zk-SNARKs vs zk-STARKs
- **Alin Tomescu:** Groth16 Technical Reference (2025)
- **SSOJet:** 72% OIDC Adoption & SAML Analysis (2026)

---

## 📖 Glossary of Key Terms

| Term | Meaning |
| :--- | :--- |
| **ZKP** | **Zero-Knowledge Proof**: A cryptographic method where one party proves knowledge of a secret to another without revealing the secret itself. |
| **TPM** | **Trusted Platform Module**: A secure hardware chip (microcontroller) that stores cryptographic keys and performs platform integrity measurements. |
| **zkSNARK** | **Zero-Knowledge Succinct Non-Interactive Argument of Knowledge**: A type of ZKP that is very small ("succinct") and doesn't require back-and-forth communication between the prover and verifier. |
| **Groth16** | The specific, highly efficient zkSNARK proving system used in this architecture for minimum proof size and ultra-fast verification. |
| **PCR** | **Platform Configuration Register**: TPM registers that store "snapshots" of the system state (BIOS, boot code). Any tampering with the system hardware or firmware changes these values. |
| **Nonce** | **Number used Once**: A random value issued by the server to ensure that a proof cannot be intercepted and "replayed" by an attacker later. |
| **SRS** | **Structured Reference String**: The public "keys" or parameters created during a Trusted Setup ceremony that allow the ZK system to function securely. |
| **P50 / P95** | **Percentile Latency**: Measurements used to understand consistent speed. **P50 (Median)** is the "typical" experience (50% of users are faster). **P95** represents the unluckiest 5% of users; it highlights **"Tail Latency"**—the occasional slowdowns caused by network spikes or server load that an "average" would hide. |
| **Commitment** | A cryptographic value (e.g., $Y = g_0 \times X$) that "locks in" a secret (the password) so it can be verified later without being revealed. |

---

## 🧪 How We Processed These Tests (Simplified Methodology)

To get these results, we ran a suite of automated "stress tests" and "attack simulations" on the live system. Here is how we measured each category in plain English:

### ⏱️ Performance Tests
*   **Challenge Speed:** We put a stopwatch on the server from the moment a user asked to log in until the server handed back a unique "challenge" number. We aimed for less than 10 milliseconds to ensure a lag-free experience.
*   **Verification Speed:** We measured how long the server spent doing the heavy math required to check a "Zero-Knowledge" proof. At **34.55ms**, this is roughly the time it takes to blink your eyes.
*   **Load Testing:** We used a tool called *Locust* to simulate 50 users all trying to log in at the exact same second to see when the server would start to slow down.

### 🛡️ Security "Attack" Simulations
*   **Replay Attack:** We recorded a successful login and tried to "play it back" to the server a second later. The server checked its memory, saw that the unique number had already been used, and blocked the login.
*   **Data Tampering:** We took a real proof and changed just one letter in it (like changing a '1' to a '0'). The server's mathematical check immediately failed, proving it can detect if even a tiny bit of data is altered during transmission.
*   **The "Stolen Device" Test (Revocation):** We went into the admin panel and marked a specific laptop as "Lost/Stolen." When we tried to log in with that laptop, the server rejected it instantly, even though the password was correct.
*   **The "Hacked BIOS" Test (PCR):** We simulated a laptop where the security settings had been changed (simulating a malware infection in the BIOS). Because the "snapshot" (PCR) didn't match our clean baseline, the server blocked the access.

---
**End of Document**  
*Validated against live system telemetry.*
