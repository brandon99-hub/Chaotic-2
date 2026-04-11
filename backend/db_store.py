"""
Database-backed User Store.
Replaces the in-memory self.users = {} dict across zkp_protocol.py and 
zkp_hardware_protocol.py so that user commitments survive server restarts.
"""
import sys
from pathlib import Path
import datetime

# Make sure the backend directory is in sys.path
_backend_dir = Path(__file__).parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from database import SessionLocal
from models import User as UserModel, Device as DeviceModel

# ---------------------------------------------------------------------------
# User store helpers (replaces self.users = {})
# ---------------------------------------------------------------------------

def get_user(hr_id: str) -> dict | None:
    """Return user commitment dict or None."""
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.hr_id == hr_id).first()
        if not user:
            return None
        return {
            "Y": int(user.Y),
            "g0": int(user.g0),
            "policy": user.policy or "default",
            "registered_at": int(user.created_at.timestamp()) if user.created_at else 0,
        }
    finally:
        db.close()


def user_exists(hr_id: str) -> bool:
    """Check if a user commitment is registered."""
    db = SessionLocal()
    try:
        return db.query(UserModel).filter(UserModel.hr_id == hr_id).count() > 0
    finally:
        db.close()


def save_user(hr_id: str, Y: int, g0: int, policy: str = "default") -> bool:
    """Persist a new user commitment. Returns False if already exists."""
    db = SessionLocal()
    try:
        if db.query(UserModel).filter(UserModel.hr_id == hr_id).first():
            return False
        user = UserModel(
            hr_id=hr_id,
            email=hr_id,  # hr_id is usually the email in this system
            g0=str(g0),
            Y=str(Y),
            policy=policy,
            is_active=True,
        )
        db.add(user)
        db.commit()
        return True
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def list_users() -> list:
    """Return all registered hr_ids."""
    db = SessionLocal()
    try:
        return [u.hr_id for u in db.query(UserModel).all()]
    finally:
        db.close()


def count_users() -> int:
    db = SessionLocal()
    try:
        return db.query(UserModel).count()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Device store helpers (replaces devices.json)
# ---------------------------------------------------------------------------

def get_device(device_id: str) -> dict | None:
    """Return device record as dict or None."""
    db = SessionLocal()
    try:
        dev = db.query(DeviceModel).filter(DeviceModel.device_id == device_id).first()
        if not dev:
            return None
        return _device_to_dict(dev)
    finally:
        db.close()


def save_device(record: dict):
    """Insert or replace a device record."""
    db = SessionLocal()
    try:
        dev = db.query(DeviceModel).filter(DeviceModel.device_id == record["device_id"]).first()
        if dev:
            _update_device_model(dev, record)
        else:
            user = db.query(UserModel).filter(UserModel.hr_id == record["user_id"]).first()
            dev = DeviceModel(
                device_id=record["device_id"],
                user_id=user.id if user else None,
            )
            _update_device_model(dev, record)
            db.add(dev)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def update_device_field(device_id: str, **kwargs):
    """Update specific fields on a device."""
    db = SessionLocal()
    try:
        dev = db.query(DeviceModel).filter(DeviceModel.device_id == device_id).first()
        if dev:
            for key, value in kwargs.items():
                setattr(dev, key, value)
            dev.last_seen = datetime.datetime.utcnow()
            db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_user_devices(user_id: str) -> list:
    """Return list of device dicts for a given user (hr_id)."""
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.hr_id == user_id).first()
        if not user:
            return []
        devs = db.query(DeviceModel).filter(DeviceModel.user_id == user.id).all()
        return [_device_to_dict(d) for d in devs]
    finally:
        db.close()


def count_devices_by_status() -> dict:
    db = SessionLocal()
    try:
        total = db.query(DeviceModel).count()
        active = db.query(DeviceModel).filter(DeviceModel.status == "active").count()
        revoked = db.query(DeviceModel).filter(DeviceModel.status == "revoked").count()
        return {"total_devices": total, "active_devices": active, "revoked_devices": revoked}
    finally:
        db.close()


def list_device_ids() -> list:
    db = SessionLocal()
    try:
        return [d.device_id for d in db.query(DeviceModel).all()]
    finally:
        db.close()


def get_audit_stats() -> dict:
    """Aggregate real-world performance and security metrics from AuditLog."""
    from models import AuditLog
    from sqlalchemy import func
    db = SessionLocal()
    try:
        # Average Latency
        avg_lat = db.query(func.avg(AuditLog.latency_ms)).filter(AuditLog.latency_ms > 0).scalar() or 0
        
        # Total counts
        total_auths = db.query(AuditLog).filter(AuditLog.event_type == "AUTH_ATTEMPT").count()
        
        # Security Probe Stats
        # We look for the 'replay_blocked' key in the security_check JSON
        replays_blocked = 0
        all_probes = db.query(AuditLog.security_check).filter(AuditLog.security_check != None).all()
        for probe in all_probes:
            if probe[0] and probe[0].get("replay_blocked"):
                replays_blocked += 1
        
        # Mocking some baseline for missing data points if necessary
        return {
            "avg_latency": float(avg_lat),
            "total_auths": total_auths,
            "replays_blocked": replays_blocked,
            "security_score": 100.0 if (total_auths == 0 or replays_blocked > 0) else 0.0 # simplified logic
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _device_to_dict(dev: DeviceModel) -> dict:
    import json
    db = SessionLocal()
    try:
        owner = db.query(UserModel).filter(UserModel.id == dev.user_id).first()
        user_hr_id = owner.hr_id if owner else None
    finally:
        db.close()

    return {
        "device_id": dev.device_id,
        "user_id": user_hr_id,
        "certificate": dev.certificate or "",
        "cert_hash": dev.cert_hash or "",
        "cert_thumbprint": dev.cert_thumbprint,
        "key_storage": dev.pcr_baseline.get("_key_storage", {}) if dev.pcr_baseline else {},
        "tpm_mode": dev.tpm_mode or "software",
        "tpm_info": {},
        "pcr_baseline": {k: v for k, v in (dev.pcr_baseline or {}).items() if not k.startswith("_")},
        "enrolled_at": int(dev.created_at.timestamp()) if dev.created_at else 0,
        "last_seen": int(dev.last_seen.timestamp()) if dev.last_seen else 0,
        "machine_alias": dev.machine_alias or "New Secure Device",
        "site_registrations": [],
        "status": dev.status or "active",
    }


def _update_device_model(dev: DeviceModel, record: dict):
    """Write fields from a dict onto a DeviceModel instance."""
    import json
    dev.status = record.get("status", "active")
    dev.machine_alias = record.get("machine_alias", "New Secure Device")
    dev.tpm_mode = record.get("tpm_mode", "software")
    dev.certificate = record.get("certificate", "")
    dev.cert_hash = record.get("cert_hash", "")
    dev.cert_thumbprint = record.get("cert_thumbprint")

    # Pack private key and pcr_baseline together into the JSON column
    pcr_data = dict(record.get("pcr_baseline", {}))
    key_storage = record.get("key_storage", {})
    if key_storage:
        pcr_data["_key_storage"] = key_storage   # piggyback on same JSON column
    dev.pcr_baseline = pcr_data
