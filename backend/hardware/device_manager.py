"""
Device enrollment and management for hardware-backed authentication.
Now backed by PostgreSQL via db_store instead of data/devices.json.
"""

import hashlib
import sys
import time
from pathlib import Path
from typing import Dict, Optional

# Ensure backend dir is on path for db_store import
_backend_dir = Path(__file__).parent.parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

import db_store
from .tpm_integration import TPMManager


class DeviceManager:
    """
    Manages device enrollment and lifecycle via PostgreSQL.
    Public API is identical to the old file-backed version.
    """

    def __init__(self, storage_path: str = "data/devices.json"):
        # storage_path kept for API compat but not used — PostgreSQL is the store
        self.tpm_manager = TPMManager()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @property
    def devices(self) -> dict:
        """Expose a dict-like view for health checks (device_id -> record)."""
        return {d["device_id"]: d for d in [
            db_store.get_device(did) for did in db_store.list_device_ids()
        ] if d}

    def _device_has_signing_material(self, device: Dict) -> bool:
        if not device:
            return False
        if device.get("cert_thumbprint"):
            return True
        return bool(device.get("key_storage", {}).get("private_key_pem"))

    # ------------------------------------------------------------------
    # Enroll
    # ------------------------------------------------------------------

    def enroll_device(self, device_id: str, user_id: str) -> Dict:
        """Enroll or rebind a device to a user."""
        now = int(time.time())
        existing_device = db_store.get_device(device_id)

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
                print("[DeviceManager] Re-provisioning missing signing material.")
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
            "machine_alias": profile.get("machine_alias", "New Secure Device"),
            "site_registrations": [],
            "status": "active",
        }

        db_store.save_device(device_record)
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

    # ------------------------------------------------------------------
    # Other operations
    # ------------------------------------------------------------------

    def log_site_registration(self, device_id: str, site_origin: str):
        """Log that this device was used on a specific site."""
        # Site registrations are low-priority metadata — skipped for now
        pass

    def update_machine_alias(self, device_id: str, new_alias: str):
        """Update the friendly name of the machine."""
        db_store.update_device_field(device_id, machine_alias=new_alias)

    def generate_attestation(
        self, device_id: str, nonce: int, timestamp: int, srs_id: str
    ) -> Dict:
        """Generate a TPM attestation object for the requested device."""
        device_record = db_store.get_device(device_id)
        if not device_record:
            raise ValueError("Device not enrolled")
        if device_record["status"] != "active":
            raise ValueError("Device is not active")
        if not self._device_has_signing_material(device_record):
            raise RuntimeError(
                "Device is missing signing material. Re-enroll this device."
            )
        return self.tpm_manager.get_attestation_quote(
            device_record, nonce, timestamp, srs_id
        )

    def get_device(self, device_id: str) -> Optional[Dict]:
        """Get device information."""
        return db_store.get_device(device_id)

    def is_device_enrolled(self, device_id: str) -> bool:
        return db_store.get_device(device_id) is not None

    def is_device_active(self, device_id: str) -> bool:
        device = db_store.get_device(device_id)
        return device is not None and device["status"] == "active"

    def revoke_device(self, device_id: str, reason: str = "User revoked") -> bool:
        device = db_store.get_device(device_id)
        if not device:
            return False
        db_store.update_device_field(device_id, status="revoked")
        print(f"[DeviceManager] Revoked device {device_id}: {reason}")
        return True

    def update_device_last_seen(self, device_id: str):
        db_store.update_device_field(device_id)  # last_seen updated automatically

    def get_user_devices(self, user_id: str) -> list:
        return db_store.get_user_devices(user_id)

    def get_device_stats(self) -> Dict:
        return db_store.count_devices_by_status()
