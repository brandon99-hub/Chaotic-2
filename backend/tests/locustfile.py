from locust import HttpUser, task, between
import random

class ChaoticAuthUser(HttpUser):
    # Simulate normal user think-time between 1 and 2 seconds
    wait_time = between(1, 2)
    
    @task(3)
    def endpoint_challenge_success(self):
        """Simulate successful challenge requests for an enrolled device"""
        self.client.post("/api/auth/challenge", json={
            "user_id": "sheisjennifer@gmail.com",
            "device_id": "HW_ERRRX8344"
        }, name="/api/auth/challenge [Success]")
        
    @task(1)
    def endpoint_challenge_failure(self):
        """Simulate malicious/invalid challenge requests"""
        uid = f"malicious_{random.randint(1000, 9999)}@attack.com"
        self.client.post("/api/auth/challenge", json={
            "user_id": uid,
            "device_id": "UNKNOWN_DEVICE"
        }, name="/api/auth/challenge [Fail]")
        
    @task(2)
    def endpoint_health(self):
        """Simulate standard background system checks"""
        self.client.get("/api/health", name="/api/health")
