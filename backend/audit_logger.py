"""
Audit logging for security-critical events.
Provides structured logging for compliance and forensics.
"""

import json
import logging
import time
from typing import Dict, Optional
from pathlib import Path


class AuditLogger:
    """
    Security audit logger for authentication events.
    
    Logs all security-critical operations:
    - Authentication attempts (success/failure)
    - Device operations (enrollment, revocation)
    - Attestation verifications
    - Policy violations
    """
    
    def __init__(self, log_file: str = "data/audit.log"):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to audit log file
        """
        self.log_file = Path(log_file)
        
        # Create logger
        self.logger = logging.getLogger("SecurityAudit")
        self.logger.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)
        
        # Formatter with all details
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        
        print(f"[AuditLogger] Initialized: {self.log_file}")
    
    def _log_event(self, event_type: str, data: Dict):
        """
        Internal method to log structured event.
        
        Args:
            event_type: Type of event
            data: Event data dictionary
        """
        audit_entry = {
            "event_type": event_type,
            "timestamp": int(time.time()),
            **data
        }
        
        self.logger.info(json.dumps(audit_entry))
    
    def log_authentication_attempt(
        self,
        user_id: str,
        device_id: str,
        success: bool,
        method: str = "zksnark_hardware",
        attestation_digest: Optional[str] = None,
        proof_hash: Optional[str] = None,
        srs_id: Optional[str] = None,
        failure_reason: Optional[str] = None,
        ip_address: Optional[str] = None
    ):
        """
        Log authentication attempt.
        
        Args:
            user_id: User attempting authentication
            device_id: Device used
            success: Whether authentication succeeded
            method: Authentication method
            attestation_digest: Attestation digest hash
            proof_hash: zkSNARK proof hash
            srs_id: SRS ID used
            failure_reason: Reason for failure (if applicable)
            ip_address: Client IP address
        """
        self._log_event("AUTH_ATTEMPT", {
            "user_id": user_id,
            "device_id": device_id,
            "success": success,
            "method": method,
            "attestation_digest": attestation_digest,
            "proof_hash": proof_hash,
            "srs_id": srs_id,
            "failure_reason": failure_reason,
            "ip_address": ip_address
        })
    
    def log_device_enrollment(
        self,
        device_id: str,
        user_id: str,
        cert_hash: str,
        tpm_mode: str
    ):
        """
        Log device enrollment.
        
        Args:
            device_id: Device identifier
            user_id: User enrolling device
            cert_hash: Device certificate hash
            tpm_mode: TPM mode (hardware/software)
        """
        self._log_event("DEVICE_ENROLLMENT", {
            "device_id": device_id,
            "user_id": user_id,
            "cert_hash": cert_hash,
            "tpm_mode": tpm_mode
        })
    
    def log_device_revocation(
        self,
        device_id: str,
        user_id: str,
        reason: str,
        revoked_by: str
    ):
        """
        Log device revocation.
        
        Args:
            device_id: Device revoked
            user_id: User owning device
            reason: Revocation reason
            revoked_by: Who revoked the device
        """
        self._log_event("DEVICE_REVOCATION", {
            "device_id": device_id,
            "user_id": user_id,
            "reason": reason,
            "revoked_by": revoked_by
        })
    
    def log_attestation_verification(
        self,
        device_id: str,
        success: bool,
        failure_reason: Optional[str] = None,
        pcr_values: Optional[Dict] = None
    ):
        """
        Log attestation verification.
        
        Args:
            device_id: Device being attested
            success: Verification result
            failure_reason: Failure reason if applicable
            pcr_values: PCR values checked
        """
        self._log_event("ATTESTATION_VERIFICATION", {
            "device_id": device_id,
            "success": success,
            "failure_reason": failure_reason,
            "pcr_count": len(pcr_values) if pcr_values else 0
        })
    
    def log_policy_violation(
        self,
        user_id: str,
        device_id: str,
        violation_type: str,
        details: str
    ):
        """
        Log policy violation.
        
        Args:
            user_id: User involved
            device_id: Device involved
            violation_type: Type of violation
            details: Violation details
        """
        self._log_event("POLICY_VIOLATION", {
            "user_id": user_id,
            "device_id": device_id,
            "violation_type": violation_type,
            "details": details
        })
    
    def log_srs_operation(
        self,
        operation: str,
        srs_id: str,
        details: Dict
    ):
        """
        Log SRS-related operation.
        
        Args:
            operation: Operation type (register, deprecate, etc.)
            srs_id: SRS identifier
            details: Operation details
        """
        self._log_event("SRS_OPERATION", {
            "operation": operation,
            "srs_id": srs_id,
            **details
        })
    
    def log_system_event(
        self,
        event: str,
        details: Dict
    ):
        """
        Log general system event.
        
        Args:
            event: Event description
            details: Event details
        """
        self._log_event("SYSTEM_EVENT", {
            "event": event,
            **details
        })


# Singleton instance
_audit_logger_instance = None

def get_audit_logger() -> AuditLogger:
    """Get singleton audit logger instance."""
    global _audit_logger_instance
    if _audit_logger_instance is None:
        _audit_logger_instance = AuditLogger()
    return _audit_logger_instance

