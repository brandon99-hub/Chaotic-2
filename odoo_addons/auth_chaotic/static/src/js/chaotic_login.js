/** @odoo-module **/
/**
 * Chaotic Hardware Login Widget
 * Handles the "Login with Hardware Proof" button on the Odoo login page.
 */

const CHAOTIC_BACKEND_URL = window.location.hostname === 'localhost'
    ? 'http://localhost:8000'
    : `${window.location.protocol}//${window.location.hostname}:8000`;

// ── Device ID persistence ────────────────────────────────────────────────────
function getOrCreateDeviceId(login) {
    const key = `chaotic_device_${login}`;
    let stored = localStorage.getItem(key);
    if (!stored) {
        const fingerprint = `${navigator.userAgent}-${navigator.platform}-${navigator.language}`;
        const hash = Array.from(fingerprint).reduce((h, c) => (((h << 5) - h) + c.charCodeAt(0)) | 0, 0);
        stored = `device_${Math.abs(hash).toString(16)}`;
        localStorage.setItem(key, stored);
    }
    return stored;
}

// ── TPM Attestation (simulated for PoC) ────────────────────────────────────
async function buildAttestation(deviceId, nonce, timestamp, srsId) {
    const enc = new TextEncoder();
    const data = `${nonce}||${timestamp}||${srsId}`;
    const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(data));
    const sig = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

    const pcrs = {};
    for (const i of [0, 1, 2, 3, 7]) {
        const pcrBuf = await crypto.subtle.digest('SHA-256', enc.encode(`PCR${i}_${deviceId}`));
        pcrs[i] = Array.from(new Uint8Array(pcrBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    return { signature: sig, pcrs, certificate: '-----BEGIN CERTIFICATE-----\nSimulated\n-----END CERTIFICATE-----', nonce: String(nonce), timestamp, srs_id: srsId, tpm_mode: 'simulation' };
}

// ── ZKP-less simple forward (for PoC: sends the proof via backend) ──────────
async function performHardwareLogin(login, statusEl) {
    const deviceId = getOrCreateDeviceId(login);

    statusEl.textContent = '🔐 Requesting hardware challenge…';
    const challengeResp = await fetch(`${CHAOTIC_BACKEND_URL}/api/auth/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: login, device_id: deviceId }),
    });

    if (!challengeResp.ok) {
        const err = await challengeResp.json();
        throw new Error(err.detail || 'Challenge request failed');
    }

    const { challenge } = await challengeResp.json();

    statusEl.textContent = '🖥️ Reading hardware TPM…';
    const attestation = await buildAttestation(deviceId, challenge.N, challenge.t, challenge.SRS_ID);

    statusEl.textContent = '🔢 Generating zkSNARK proof… (10-30s)';

    // Fetch stored user data to build proof
    const userResp = await fetch(`${CHAOTIC_BACKEND_URL}/api/users/${encodeURIComponent(login)}/data`);
    if (!userResp.ok) throw new Error('User not found — did you sign up with Chaotic first?');
    const userData = await userResp.json();

    // Load snarkjs dynamically (must be in static assets or CDN)
    if (typeof snarkjs === 'undefined') {
        throw new Error('snarkjs not loaded. Check your Odoo asset configuration.');
    }

    // We cannot hash the password here without it — in Odoo context we should
    // prompt the user for their Chaotic password in a small popup.
    // For the PoC: the password field on the Odoo form IS the Chaotic password.
    const passwordInput = document.querySelector('input[name="password"]');
    if (!passwordInput || !passwordInput.value) {
        throw new Error('Please enter your Chaotic password in the password field.');
    }

    const { hashPasswordToField, computeCommitment } = window.ChaoticCrypto || {};
    if (!hashPasswordToField) throw new Error('ChaoticCrypto not loaded');

    const secretX = await hashPasswordToField(passwordInput.value);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        { x: secretX.toString(), g0: userData.g0, Y: userData.Y },
        '/static/auth_chaotic/wasm/auth.wasm',
        '/static/auth_chaotic/zkey/auth_final.zkey'
    );

    statusEl.textContent = '✅ Verifying with server…';
    const verifyResp = await fetch('/web/login/chaotic_verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ login, proof, public_signals: publicSignals, attestation, nonce: challenge.N, device_id: deviceId }),
    });

    const result = await verifyResp.json();
    if (result.success) {
        window.location.href = result.redirect || '/web';
    } else {
        throw new Error(result.error || 'Authentication failed');
    }
}

// ── DOM wiring ───────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('chaotic_hardware_login_btn');
    if (!btn) return;

    // Inject status panel
    const statusEl = document.createElement('div');
    statusEl.className = 'alert alert-info mt-2 d-none';
    btn.parentElement.insertBefore(statusEl, btn.nextSibling);

    btn.addEventListener('click', async () => {
        const loginInput = document.querySelector('input[name="login"]');
        if (!loginInput || !loginInput.value.trim()) {
            alert('Please enter your username/email first.');
            return;
        }

        btn.disabled = true;
        statusEl.classList.remove('d-none');

        try {
            await performHardwareLogin(loginInput.value.trim(), statusEl);
        } catch (err) {
            statusEl.className = 'alert alert-danger mt-2';
            statusEl.textContent = `❌ ${err.message}`;
            btn.disabled = false;
        }
    });
});
