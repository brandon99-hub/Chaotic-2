from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
import datetime
try:
    from database import Base
except ImportError:
    from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    hr_id = Column(String, unique=True, index=True, nullable=False) # The employee/user ID
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    
    # ZK Commitments
    g0 = Column(Text, nullable=False) # Random field element (stored as string for precision)
    Y = Column(Text, nullable=False)  # Commitment g0 * X (stored as string)
    
    # Policy and Status
    policy = Column(String, default="default")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    devices = relationship("Device", back_populates="owner")
    auth_logs = relationship("AuditLog", back_populates="user")

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    machine_alias = Column(String)
    status = Column(String, default="active") # active, revoked, pending
    
    # TPM Metadata
    tpm_mode = Column(String) # windows, linux, software
    certificate = Column(Text)
    cert_hash = Column(String)
    cert_thumbprint = Column(String)
    pcr_baseline = Column(JSON) # Snapshot of PCRs at enrollment
    
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    owner = relationship("User", back_populates="devices")
    auth_logs = relationship("AuditLog", back_populates="device")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    device_id = Column(Integer, ForeignKey("devices.id"))
    
    event_type = Column(String) # login, enrollment, revocation, etc.
    success = Column(Boolean)
    failure_reason = Column(String)
    
    # Cryptographic Proofs for the Transparency Ledger
    attestation_digest = Column(String)
    proof_hash = Column(String)
    srs_id = Column(String)
    
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String)
    
    user = relationship("User", back_populates="auth_logs")
    device = relationship("Device", back_populates="auth_logs")
