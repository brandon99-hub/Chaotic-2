import requests
import json
import time

# --- MOCK DATA (Simulating the exactly what api.py sends) ---
URL = "http://localhost:8088/api/auth/verify"
DATA = {
    "user_id": "nobodylaxus@gmail.com",
    "device_id": "AUTO", # This is what the bridge currently sends
    "proof": {"machine_verified": True},
    "attestation": {"type": "tpm_software"},
    "nonce": 123456789, # Simulation
    "timestamp": int(time.time()),
    "public_signals": ["nobodylaxus@gmail.com", "HW_TEST", "123456789"]
}

print(f"--- Sending Probe to {URL} ---")
print(f"Payload: {json.dumps(DATA, indent=2)}")

try:
    response = requests.post(URL, json=DATA)
    print(f"\nSTATUS CODE: {response.status_code}")
    print(f"RESPONSE BODY: {response.text}")
    
    if response.status_code == 422:
        print("\n[AHA!] Found the Validation Error. Details above.")
except Exception as e:
    print(f"Connection Failed: {e}")
