"""
Device enrollment and management for hardware-backed authentication.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Dict, Optional

from .tpm_integration import TPMManager


class DeviceManager:
    """
    Manages device enrollment and lifecycle.
    
    Handles:
    - Device registration with TPM attestation
    - Certificate issuance and management
    - Device revocation
    - Device state tracking
    """
    
    def __init__(self, storage_path: str = "devices.json"):
        """
        Initialize device manager.
        
        Args:
            storage_path: Path to store device registry
        """
        self.storage_path = Path(storage_path)
        self.devices = self._load_devices()
        self.tpm_manager = TPMManager()
    
    def _load_devices(self) -> Dict:
        """Load device registry from disk."""
        if self.storage_path.exists():
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_devices(self):
        """Save device registry to disk."""
        with open(self.storage_path, 'w') as f:
            json.dump(self.devices, f, indent=2)
    
    def _device_has_signing_material(self, device: Dict) -> bool:
        """Return True if device has either TPM thumbprint or software key."""
        if not device:
            return False
        if device.get("cert_thumbprint"):
            return True
        key_storage = device.get("key_storage", {})
        return bool(key_storage.get("private_key_pem"))

    def enroll_device(self, device_id: str, user_id: str) -> Dict:
        """
        Enroll or rebind a device to a user.
        """
        now = int(time.time())
        existing_device = self.devices.get(device_id)

        reprovision_required = False
        if existing_device:
            same_user = existing_device["user_id"] == user_id
            active = existing_device["status"] == "active"
            has_material = self._device_has_signing_material(existing_device)

            if same_user and active and has_material:
                return {
                    "success": True,
                    "device_id": device_id,
                    "certificate": existing_device["certificate"],
                    "cert_hash": existing_device["cert_hash"],
                    "enrolled_at": existing_device["enrolled_at"],
                    "tpm_mode": existing_device.get("tpm_mode"),
                    "message": "Device already enrolled for this user",
                }

            if same_user and active and not has_material:
                reprovision_required = True
                print(
                    "[DeviceManager] Existing device is missing signing material; "
                    "re-provisioning TPM keys."
                )
            print(
                f"[DeviceManager] Rebinding device {device_id} "
                f"from {existing_device['user_id']} to {user_id}"
            )

        profile = self.tpm_manager.generate_device_key(device_id)
        certificate = profile["certificate"]
        cert_hash = hashlib.sha256(certificate.encode()).hexdigest()

        pcrs = self.tpm_manager.read_pcrs()

        device_record = {
            "device_id": device_id,
            "user_id": user_id,
            "certificate": certificate,
            "cert_hash": cert_hash,
            "cert_thumbprint": profile.get("cert_thumbprint"),
            "key_storage": profile.get("key_storage", {}),
            "tpm_mode": profile.get("mode", self.tpm_manager.tpm_mode),
            "tpm_info": profile.get("tpm_info", self.tpm_manager.get_tpm_info()),
            "pcr_baseline": {str(k): v.hex() for k, v in pcrs.items()},
            "enrolled_at": now,
            "last_seen": now,
            "status": "active",
        }

        self.devices[device_id] = device_record
        self._save_devices()

        print(f"[DeviceManager] Enrolled device {device_id} for user {user_id}")

        response = {
            "success": True,
            "device_id": device_id,
            "certificate": certificate,
            "cert_hash": cert_hash,
            "enrolled_at": device_record["enrolled_at"],
            "tpm_mode": device_record["tpm_mode"],
        }

        if existing_device:
            if existing_device["user_id"] != user_id:
                response["message"] = "Device re-enrolled with new certificate"
            elif reprovision_required:
                response["message"] = "Device repaired with new signing material"

        return response

    def generate_attestation(
        self, device_id: str, nonce: int, timestamp: int, srs_id: str
    ) -> Dict:
        """
        Generate a TPM attestation object for the requested device.
        """
        device_record = self.devices.get(device_id)
        if not device_record:
            raise ValueError("Device not enrolled")
        if device_record["status"] != "active":
            raise ValueError("Device is not active")
        if not self._device_has_signing_material(device_record):
            raise RuntimeError(
                "Device is missing signing material. Re-enroll this device to repair it."
            )

        attestation = self.tpm_manager.get_attestation_quote(
            device_record, nonce, timestamp, srs_id
        )
        return attestation
    
    def get_device(self, device_id: str) -> Optional[Dict]:
        """Get device information."""
        return self.devices.get(device_id)
    
    def is_device_enrolled(self, device_id: str) -> bool:
        """Check if device is enrolled."""
        return device_id in self.devices
    
    def is_device_active(self, device_id: str) -> bool:
        """Check if device is active (not revoked)."""
        device = self.devices.get(device_id)
        return device is not None and device["status"] == "active"
    
    def revoke_device(self, device_id: str, reason: str = "User revoked") -> bool:
        """
        Revoke a device.
        
        Args:
            device_id: Device to revoke
            reason: Revocation reason
        
        Returns:
            Success status
        """
        if device_id not in self.devices:
            return False
        
        self.devices[device_id]["status"] = "revoked"
        self.devices[device_id]["revoked_at"] = int(time.time())
        self.devices[device_id]["revocation_reason"] = reason
        self._save_devices()
        
        print(f"[DeviceManager] Revoked device {device_id}: {reason}")
        return True
    
    def update_device_last_seen(self, device_id: str):
        """Update device last seen timestamp."""
        if device_id in self.devices:
            self.devices[device_id]["last_seen"] = int(time.time())
            self._save_devices()
    
    def get_user_devices(self, user_id: str) -> list:
        """Get all devices for a user."""
        return [
            device for device in self.devices.values()
            if device["user_id"] == user_id
        ]
    
    def get_device_stats(self) -> Dict:
        """Get device statistics."""
        total = len(self.devices)
        active = sum(1 for d in self.devices.values() if d["status"] == "active")
        revoked = sum(1 for d in self.devices.values() if d["status"] == "revoked")
        
        return {
            "total_devices": total,
            "active_devices": active,
            "revoked_devices": revoked
        }

