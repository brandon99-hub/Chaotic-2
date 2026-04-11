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
    nonce = chall_res.json()["nonce"]

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
    assert res2.status_code == 401
    assert "Challenge" in res2.json()["detail"] or "expired" in res2.json()["detail"].lower()

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
    nonce = chall["nonce"]
    
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
