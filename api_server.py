from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Dict, List, Optional
import uvicorn
from zkp_protocol import Server, Client
from hash_utils import reduce_to_field
import os
from pathlib import Path

# Import hardware components
try:
    from zkp_hardware_protocol import HardwareAttestedServer
    from hardware.device_manager import DeviceManager
    from srs.srs_manager import SRSManager
    from srs.ledger import TransparencyLedger
    from audit_logger import get_audit_logger
    HARDWARE_AVAILABLE = True
except ImportError:
    HARDWARE_AVAILABLE = False
    print("[Warning] Hardware attestation modules not available - running in simple mode only")

app = FastAPI(
    title="zkSNARK Authentication API",
    description="Passwordless authentication using Zero-Knowledge Proofs + Hardware Attestation",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple mode server
server_instance = Server()

# Hardware mode server (if available)
if HARDWARE_AVAILABLE:
    hw_server = HardwareAttestedServer()
    device_manager = hw_server.device_manager
    srs_manager = hw_server.srs_manager
    ledger = hw_server.ledger
    audit_logger = hw_server.audit_logger
else:
    hw_server = None


class RegisterRequest(BaseModel):
    hr_id: str
    Y: str
    g0: str


class LoginRequest(BaseModel):
    hr_id: str
    proof: Dict
    public_signals: List[str]


# Hardware mode request models
class DeviceEnrollmentRequest(BaseModel):
    device_id: str
    user_id: str


class DeviceAttestationRequest(BaseModel):
    user_id: str
    device_id: str
    nonce: str
    timestamp: int
    srs_id: str


class ChallengeRequest(BaseModel):
    user_id: str
    device_id: str


class HardwareAuthRequest(BaseModel):
    user_id: str
    device_id: str
    nonce: int
    attestation: Dict
    proof: Dict
    public_signals: List[str]


class DeviceRevocationRequest(BaseModel):
    device_id: str
    reason: str


@app.get("/")
async def root():
    return {
        "message": "zkSNARK Authentication API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/api/health",
            "register_g0": "/api/register/g0",
            "register": "/api/register",
            "user_data": "/api/users/{hr_id}/data",
            "login": "/api/login"
        }
    }


@app.get("/api/health")
async def health_check():
    health_data = {
        "status": "healthy",
        "mode": "simple+hardware" if HARDWARE_AVAILABLE else "simple_only",
        "users_registered": len(server_instance.users)
    }
    
    if HARDWARE_AVAILABLE:
        health_data["devices"] = device_manager.get_device_stats()
        health_data["srs"] = srs_manager.get_srs_stats()
        health_data["ledger"] = ledger.get_stats()
    
    return health_data


@app.get("/api/register/g0")
async def get_g0():
    try:
        g0 = server_instance.get_random_g0()
        return {"g0": str(g0)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate g0: {str(e)}")


@app.post("/api/register")
async def register_user(request: RegisterRequest):
    try:
        Y = reduce_to_field(int(request.Y))
        g0 = reduce_to_field(int(request.g0))
        
        # Register in both simple and hardware mode
        success, message = server_instance.register_user(
            request.hr_id,
            Y,
            g0
        )
        
        # Also register in hardware server if available
        if HARDWARE_AVAILABLE and success:
            hw_server.register_user(request.hr_id, Y, g0, request.policy if hasattr(request, 'policy') else "default")
        
        if not success:
            raise HTTPException(status_code=400, detail=message)
        
        return {
            "success": True,
            "message": message,
            "hr_id": request.hr_id
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.get("/api/users/{hr_id}/data")
async def get_user_data(hr_id: str):
    # Check simple mode server first
    if hr_id in server_instance.users:
        user_data = server_instance.users[hr_id]
        return {
            "g0": str(user_data["g0"]),
            "Y": str(user_data["Y"]),
            "policy": user_data.get("policy", "default")
        }
    
    # Check hardware mode server if available
    if HARDWARE_AVAILABLE and hr_id in hw_server.users:
        user_data = hw_server.users[hr_id]
        return {
            "g0": str(user_data["g0"]),
            "Y": str(user_data["Y"]),
            "policy": user_data.get("policy", "default")
        }
    
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/api/login")
async def login_user(request: LoginRequest):
    try:
        success, message = server_instance.authenticate_user(
            request.hr_id,
            request.proof,
            request.public_signals
        )
        
        if not success:
            raise HTTPException(status_code=401, detail=message)
        
        return {
            "success": True,
            "message": message,
            "hr_id": request.hr_id
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")


@app.get("/api/users")
async def list_users():
    return {
        "users": list(server_instance.users.keys()),
        "count": len(server_instance.users)
    }


# ==================== HARDWARE ATTESTATION ENDPOINTS ====================

if HARDWARE_AVAILABLE:
    
    @app.post("/api/devices/enroll")
    async def enroll_device(request: DeviceEnrollmentRequest):
        """Enroll device with TPM attestation"""
        try:
            result = device_manager.enroll_device(request.device_id, request.user_id)
            if result["success"]:
                ledger.log_device_enrollment(request.device_id, request.user_id, result["cert_hash"])
                audit_logger.log_device_enrollment(
                    request.device_id, request.user_id, result["cert_hash"],
                    result.get("tpm_info", {}).get("mode", "unknown")
                )
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/devices/attest")
    async def generate_device_attestation(request: DeviceAttestationRequest):
        """Produce TPM attestation for a device (local TPM helper)."""
        try:
            device = device_manager.get_device(request.device_id)
            if not device:
                raise HTTPException(status_code=404, detail="Device not enrolled")
            if device["user_id"] != request.user_id:
                raise HTTPException(status_code=403, detail="Device does not belong to user")
            if device.get("status") != "active":
                raise HTTPException(status_code=400, detail="Device is not active")

            nonce_value = int(request.nonce)
            attestation = device_manager.generate_attestation(
                request.device_id,
                nonce_value,
                request.timestamp,
                request.srs_id
            )

            return {"success": True, "attestation": attestation}
        except HTTPException:
            raise
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    
    @app.get("/api/devices/{device_id}")
    async def get_device_info(device_id: str):
        """Get device information"""
        device = device_manager.get_device(device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return device
    
    
    @app.get("/api/devices/user/{user_id}")
    async def get_user_devices(user_id: str):
        """Get all devices for a user"""
        devices = device_manager.get_user_devices(user_id)
        return {"user_id": user_id, "devices": devices, "count": len(devices)}
    
    
    @app.post("/api/devices/revoke")
    async def revoke_device(request: DeviceRevocationRequest):
        """Revoke a device"""
        success = device_manager.revoke_device(request.device_id, request.reason)
        if not success:
            raise HTTPException(status_code=404, detail="Device not found")
        
        device = device_manager.get_device(request.device_id)
        ledger.log_device_revocation(request.device_id, request.reason)
        audit_logger.log_device_revocation(
            request.device_id, device["user_id"], request.reason, "api_user"
        )
        return {"success": True, "message": f"Device {request.device_id} revoked"}
    
    
    @app.get("/api/devices")
    async def list_devices():
        """List all devices"""
        return {
            "devices": list(device_manager.devices.keys()),
            "stats": device_manager.get_device_stats()
        }
    
    
    @app.post("/api/auth/challenge")
    async def request_challenge(request: ChallengeRequest):
        """Request authentication challenge"""
        try:
            result = hw_server.initiate_authentication(request.user_id, request.device_id)
            if not result["success"]:
                raise HTTPException(status_code=400, detail=result["error"])
            return result
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    
    @app.post("/api/auth/verify")
    async def verify_hardware_auth(request: HardwareAuthRequest, req: Request):
        """Verify hardware-attested authentication"""
        try:
            success, message = hw_server.verify_authentication(
                request.user_id, request.device_id, request.nonce,
                request.attestation, request.proof, request.public_signals
            )
            
            if not success:
                raise HTTPException(status_code=401, detail=message)
            
            return {
                "success": True,
                "message": message,
                "user_id": request.user_id,
                "device_id": request.device_id,
                "authenticated_with": "hardware_attestation"
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    
    @app.get("/api/audit/recent")
    async def get_recent_audit(count: int = 100, event_type: Optional[str] = None):
        """Get recent audit entries"""
        entries = ledger.get_recent_entries(count, event_type)
        return {"entries": entries, "count": len(entries)}
    
    
    @app.get("/api/audit/user/{user_id}")
    async def get_user_audit(user_id: str, limit: int = 50):
        """Get user's authentication history"""
        history = ledger.get_user_auth_history(user_id, limit)
        return {"user_id": user_id, "history": history, "count": len(history)}
    
    
    @app.get("/api/audit/device/{device_id}")
    async def get_device_audit(device_id: str):
        """Get device audit history"""
        history = ledger.get_device_history(device_id)
        return {"device_id": device_id, "history": history, "count": len(history)}
    
    
    @app.get("/api/audit/verify")
    async def verify_ledger():
        """Verify ledger integrity"""
        is_valid = ledger.verify_ledger_integrity()
        return {
            "integrity_valid": is_valid,
            "message": "Ledger integrity verified" if is_valid else "Ledger compromised!"
        }
    
    
    @app.get("/api/srs")
    async def list_srs():
        """List SRS ceremonies"""
        return {
            "srs_list": srs_manager.srs_registry,
            "stats": srs_manager.get_srs_stats(),
            "default_srs": srs_manager.get_default_srs_id()
        }
    
    
    @app.get("/api/srs/{srs_id}")
    async def get_srs_info(srs_id: str):
        """Get SRS information"""
        srs = srs_manager.get_srs(srs_id)
        if not srs:
            raise HTTPException(status_code=404, detail="SRS not found")
        return srs


static_dir = Path("static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")


def start_server(host: str = "0.0.0.0", port: int = 8000):
    print("\n" + "=" * 60)
    print("    zkSNARK Authentication API Server")
    print("=" * 60)
    print(f"\nServer starting on http://{host}:{port}")
    print(f"API Documentation: http://{host}:{port}/docs")
    print(f"Health Check: http://{host}:{port}/api/health")
    print("\nPress CTRL+C to stop the server")
    print("=" * 60 + "\n")
    
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    start_server()

