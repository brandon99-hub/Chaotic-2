# Odoo Integration: zkSNARK + Hardware Attestation

## Goal

Integrate the **Chaotic** authentication system with Odoo SaaS/On-Premise so that users can log into Odoo using a **Zero-Knowledge Proof (ZKP)** backed by their machine's **TPM hardware chip**, instead of (or in addition to) a standard password.

---

## Prerequisites

| Requirement | Why |
|---|---|
| Odoo **Custom Plan** (Odoo.sh or On-Premise) | Standard SaaS plans lock out custom Python modules and external API calls |
| A running **Chaotic FastAPI Backend** (`api_server.py`) | This is the verification authority that Odoo defers to |
| A **GitHub Repository** linked to Odoo.sh | Odoo.sh deploys code by pulling from GitHub automatically |

---

## Architecture: The Bridge Pattern

Odoo itself does not know about zkSNARKs. Our integration uses a **Bridge Architecture**:

```
User (Browser)
    |
    |  (1) Clicks "Login with Hardware"
    ↓
Odoo Login Page  ←── auth_chaotic JS (chaotic_login.js)
    |
    |  (2) POST /web/login/chaotic_verify
    |      { login, proof, attestation_quote, nonce, timestamp }
    ↓
Odoo Python Controller (controllers/main.py)
    |
    |  (3) Forwards to Chaotic FastAPI
    ↓
FastAPI Backend (/api/auth/verify)
    |
    |  (4) Verifies ZK Proof + TPM Certificate
    ↓
    |  (5) Returns { success: true }
    ↓
Odoo Controller ── authenticates Odoo session
    |
    ↓
User lands on Odoo Dashboard 🎉
```

---

## Module Structure: `auth_chaotic`

Located at `odoo_addons/auth_chaotic/`.

```
auth_chaotic/
├── __manifest__.py          # Module metadata & dependencies
├── __init__.py              # Imports models + controllers
├── models/
│   ├── __init__.py
│   └── res_users.py         # Extends res.users with hardware auth fields
├── controllers/
│   ├── __init__.py
│   └── main.py              # The verification proxy endpoint
├── static/
│   └── src/
│       └── js/
│           └── chaotic_login.js  # Frontend: "Login with Hardware" button
└── views/
    └── chaotic_login_templates.xml  # Injects button into Odoo login page
```

---

## File-by-File Breakdown

### `__manifest__.py`
Declares the module. Key points:
- `depends`: `['base', 'web']` — Minimal dependencies, no extra Odoo apps needed.
- `assets`: Registers `chaotic_login.js` into Odoo's asset pipeline for the login page.

### `models/res_users.py`
Extends the standard Odoo `res.users` model with two fields:
- `chaotic_enabled` (Boolean): Flags whether a user has opted into hardware auth.
- `chaotic_device_ids` (Char): Stores the authorized TPM device IDs for this user.

### `controllers/main.py`
The core of the integration. Route: `POST /web/login/chaotic_verify`.

**Payload received from the browser:**
```json
{
  "login": "brandon@example.com",
  "proof": "<zkSNARK_proof_bytes>",
  "attestation_quote": "<TPM_quote_bytes>",
  "nonce": 1708109999,
  "timestamp": 1708109999
}
```

**What the controller does:**
1. Forwards the full payload to the **Chaotic FastAPI** at `http://localhost:8000/api/auth/verify`.
2. If the FastAPI returns `{ "success": true }`, it looks up the Odoo user by login email.
3. Calls `request.session.authenticate()` to create a valid Odoo session — without ever validating the password itself.

### `static/src/js/chaotic_login.js`
An Odoo public widget that:
1. Adds a "Login with Hardware Proof" button to the standard login form.
2. On click, reads the email from the form field.
3. Calls the backend route `/web/login/chaotic_verify` with the ZKP + TPM payload.
4. On success, redirects to `/web` (the Odoo dashboard).

> **Note**: In the full implementation, `snarkjs` would be loaded to perform in-browser proof generation. For the PoC, the proof is simulated with a placeholder while the flow and routing are validated.

### `views/chaotic_login_templates.xml`
Uses Odoo's `inherit_id="web.login"` to inject the hardware login button into the standard UI without modifying any Odoo core files.

---

## Deployment to Odoo.sh

Since Odoo Online (SaaS) does not support custom Python code, the module must be deployed via **Odoo.sh**:

1. **Link GitHub**: Your Odoo.sh project must be linked to a GitHub repository.
2. **Push the module**: Push the `odoo_addons/auth_chaotic/` folder to the linked GitHub repository.
3. **Odoo.sh builds automatically**: Odoo.sh detects the new commit, runs a build, and makes the module installable.
4. **Install the module**:
   - Activate Developer Mode in Odoo (`Settings > Developer Tools`).
   - Go to `Apps > Update Apps List`.
   - Search for "Chaotic Hardware Authentication" and click **Install**.

---

## Why Odoo is Valuable as a Test Target

Odoo is a full-featured Enterprise ERP/CRM system protecting real business data (invoices, payroll, customer records). By successfully integrating Chaotic Auth with Odoo, we demonstrate that:

1. **The math works with real systems**: Odoo's session management is production-grade.
2. **Zero-password**: No password is ever sent to Odoo's database. The ZK-proof alone is the credential.
3. **Hardware-binding**: Even if someone steals your Odoo credentials, they cannot log in without your specific laptop's TPM chip.
