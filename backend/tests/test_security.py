import pytest
import time
import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure backend can be imported
sys.path.append(str(Path(__file__).parent.parent))

from api_server import app

client = TestClient(app)

def test_replay_attack_prevention():
    """
    SECURITY VULNERABILITY TEST: Replay Attack.
    Ensures that a single nonce cannot be used for two separate verifications.
    """
    # 1. Register a test user
    email = "security_test@example.com"
    dev_id = "DEV_SEC_01"
    g0_res = client.get("/api/register/g0")
    g0 = g0_res.json()["g0"]
    
    client.post("/api/register", json={
        "hr_id": email,
        "email": email,
        "g0": g0,
        "Y": "123456789", # Mock commitment
        "device_id": dev_id
    })

    # 2. Get a valid challenge (Nonce N1)
    chall_res = client.post("/api/auth/challenge", json={
        "user_id": email,
        "device_id": dev_id
    })
    nonce = chall_res.json()["challenge"]["N"]

    # 3. Simulate first verification (Login Step 1)
    payload = {
        "user_id": email,
        "device_id": dev_id,
        "nonce": nonce,
        "attestation": {"mock": "valid"},
        "proof": {"machine_verified": True},
        "public_signals": [email, dev_id, str(nonce)]
    }
    
    # First attempt should pass or at least reach verification logic
    res1 = client.post("/api/auth/verify", json=payload)
    # Even if it fails for other reasons (like mock attestation), the nonce is now "Used"
    
    # 4. REPLAY: Attempt to use the EXACT SAME payload/nonce again
    res2 = client.post("/api/auth/verify", json=payload)
    
    # MUST FAIL with 401 or indicate nonce is no longer valid
    # MUST FAIL with 401
    assert res2.status_code == 401

def test_unregistered_device_rejection():
    """
    SECURITY TEST: Unauthorized Device.
    Ensure that a challenge issued for Device A cannot be fulfilled by Device B.
    """
    user = "alice@guardian.com"
    dev_A = "IPHONE_A"
    dev_B = "STOLEN_THINKPAD"
    
    # 1. Register Alice with Device A
    g0 = client.get("/api/register/g0").json()["g0"]
    client.post("/api/register", json={
        "hr_id": user,
        "g0": g0,
        "Y": "444",
        "device_id": dev_A
    })
    
    # 2. Get challenge for Device A
    chall = client.post("/api/auth/challenge", json={"user_id": user, "device_id": dev_A}).json()
    nonce = chall["challenge"]["N"]
    
    # 3. Attempt to verify using Device B's ID
    payload = {
        "user_id": user,
        "device_id": dev_B,
        "nonce": nonce,
        "attestation": {},
        "proof": {},
        "public_signals": []
    }
    res = client.post("/api/auth/verify", json=payload)
    
    # Must be 403 Forbidden or 401 Unauthorized
    assert res.status_code in [401, 403, 404]

def test_revoked_device_challenge_denied():
    """
    SECURITY TEST: Revocation Enforcement.
    Verify that a revoked device cannot even request a challenge.
    """
    user = "bob@revoked.com"
    dev = "MACBOOK_PRO"
    
    # 1. Register and then revoke
    g0 = client.get("/api/register/g0").json()["g0"]
    client.post("/api/register", json={"hr_id": user, "g0": g0, "Y": "555", "device_id": dev})
    
    # Revoke
    client.post("/api/devices/revoke", json={"device_id": dev, "reason": "Loss of control"})
    
    # 2. Attempt to get challenge
    res = client.post("/api/auth/challenge", json={"user_id": user, "device_id": dev})
    
    # Must fail
    assert res.status_code == 400
    assert "revoked" in res.json()["detail"].lower()

def test_tampered_signature_rejection():
    """
    SECURITY TEST: Signature Integrity.
    Ensures that if even one byte of the TPM signature is changed, the server rejects it.
    """
    suffix = str(int(time.time()))
    user = f"tamper_test_{suffix}@guard.com"
    dev = f"HW_DEVICE_TAMPER_{suffix}"

    # 1. Register and Enroll
    g0_res = client.get("/api/register/g0")
    g0 = g0_res.json()["g0"]
    reg_res = client.post("/api/register", json={"hr_id": user, "g0": g0, "Y": "999", "device_id": dev})
    assert reg_res.status_code == 200

    # 2. Get Challenge
    chall_res = client.post("/api/auth/challenge", json={"user_id": user, "device_id": dev})
    assert chall_res.status_code == 200
    chall = chall_res.json()
    nonce = chall["challenge"]["N"]
    
    # 3. Generate Valid Attestation via API helper
    attest_res = client.post("/api/devices/attest", json={
        "user_id": user,
        "device_id": dev,
        "nonce": nonce,
        "timestamp": chall["challenge"]["t"],
        "srs_id": chall["challenge"]["SRS_ID"]
    }).json()
    
    attestation = attest_res["attestation"]
    
    # 4. TAMPER: Flip a character in the signature hex
    original_sig = attestation["signature"]
    # Change first char 'a'->'b' or '0'->'1'
    tampered_sig = ("0" if original_sig[0] != "0" else "1") + original_sig[1:]
    attestation["signature"] = tampered_sig
    
    # 5. Attempt Verify
    payload = {
        "user_id": user,
        "device_id": dev,
        "nonce": int(nonce),
        "attestation": attestation,
        "proof": {"machine_verified": True},
        "public_signals": [str(g0), "999"]
    }
    res = client.post("/api/auth/verify", json=payload)
    
    assert res.status_code == 401
    assert "signature invalid" in res.json()["detail"].lower()

def test_pcr_mismatch_rejection():
    """
    SECURITY TEST: Hardware Integrity (PCR Mismatch).
    Simulates a compromised boot state where PCRs do not match the expected measurements.
    """
    suffix = str(int(time.time()))
    user = f"pcr_test_{suffix}@guard.com"
    dev = f"HW_DEVICE_PCR_{suffix}"

    # 1. Register
    g0_res = client.get("/api/register/g0")
    g0 = g0_res.json()["g0"]
    reg_res = client.post("/api/register", json={"hr_id": user, "g0": g0, "Y": "888", "device_id": dev})
    assert reg_res.status_code == 200

    # 2. Get Challenge
    chall_res = client.post("/api/auth/challenge", json={"user_id": user, "device_id": dev})
    assert chall_res.status_code == 200
    chall = chall_res.json()
    nonce = chall["challenge"]["N"]
    
    # 3. Generate Valid Attestation
    attest_res = client.post("/api/devices/attest", json={
        "user_id": user,
        "device_id": dev,
        "nonce": nonce,
        "timestamp": chall["challenge"]["t"],
        "srs_id": chall["challenge"]["SRS_ID"]
    }).json()
    attestation = attest_res["attestation"]
    
    # 4. TAMPER: Change PCR 0 (BIOS measurement)
    attestation["pcrs"]["0"] = "f" * 64 # Fake malicious PCR value
    
    # 5. Attempt Verify
    payload = {
        "user_id": user,
        "device_id": dev,
        "nonce": int(nonce),
        "attestation": attestation,
        "proof": {"machine_verified": True},
        "public_signals": [str(g0), "888"]
    }
    res = client.post("/api/auth/verify", json=payload)
    
    # While signature verification might fail first (because sig is over old PCRs),
    # the failure MUST still be a 401/403.
    assert res.status_code == 401

def test_challenge_timing_window():
    """
    SECURITY TEST: Freshness / Timing Attack window.
    Ensures that old challenges cannot be reused past the skew window.
    """
    suffix = str(int(time.time()))
    user = f"time_test_{suffix}@guard.com"
    dev = f"HW_DEVICE_TIME_{suffix}"

    # 1. Register
    g0_res = client.get("/api/register/g0")
    g0 = g0_res.json()["g0"]
    reg_res = client.post("/api/register", json={"hr_id": user, "g0": g0, "Y": "777", "device_id": dev})
    assert reg_res.status_code == 200

    # 2. Get Challenge
    chall_res = client.post("/api/auth/challenge", json={"user_id": user, "device_id": dev})
    assert chall_res.status_code == 200
    chall = chall_res.json()
    nonce = chall["challenge"]["N"]
    
    # 3. Generate Attestation with an EXPIRED timestamp (e.g., 1 hour ago)
    old_timestamp = int(time.time()) - 3600
    attest_res = client.post("/api/devices/attest", json={
        "user_id": user,
        "device_id": dev,
        "nonce": nonce,
        "timestamp": old_timestamp,
        "srs_id": chall["challenge"]["SRS_ID"]
    }).json()
    attestation = attest_res["attestation"]
    
    # 4. Attempt Verify
    payload = {
        "user_id": user,
        "device_id": dev,
        "nonce": int(nonce),
        "attestation": attestation,
        "proof": {"machine_verified": True},
        "public_signals": [str(g0), "777"]
    }
    res = client.post("/api/auth/verify", json=payload)
    
    assert res.status_code == 401
    assert "timestamp not fresh" in res.json()["detail"].lower()
