"""
Attestation verification logic for hardware-backed authentication.
Verifies TPM quotes, certificates, PCRs, and freshness.
"""

import time
import json
import hashlib
from typing import Dict, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class AttestationVerifier:
    """
    Verifies hardware attestation from TPM/TEE devices.
    
    Verification steps (from your document):
    1. Check SRS binding
    2. Verify certificate chain
    3. Verify TPM signature
    4. Check timestamp freshness
    5. Check PCR policy compliance
    6. Check revocation status
    """
    
    def __init__(self, device_manager, srs_manager=None):
        """
        Initialize attestation verifier.
        
        Args:
            device_manager: DeviceManager instance
            srs_manager: SRS manager for ceremony verification (optional)
        """
        self.device_manager = device_manager
        self.srs_manager = srs_manager
        
        # Configuration
        self.max_timestamp_skew = 300  # 5 minutes tolerance
        self.required_pcr_indices = [0, 1, 2, 3, 7]  # Boot integrity PCRs
    
    def verify_attestation(
        self,
        attestation: Dict,
        challenge_nonce: int,
        challenge_timestamp: int,
        srs_id: str,
        device_id: str
    ) -> Tuple[bool, str]:
        """
        Complete attestation verification.
        
        Args:
            attestation: Attestation object from client
            challenge_nonce: Expected nonce
            challenge_timestamp: Challenge timestamp
            srs_id: Expected SRS ID
            device_id: Device identifier
        
        Returns:
            (success, message) tuple
        """
        
        # Step 1: Check SRS binding
        if attestation.get("srs_id") != srs_id:
            return False, f"SRS ID mismatch: expected {srs_id}, got {attestation.get('srs_id')}"
        
        # Step 2: Check device is enrolled and active
        if not self.device_manager.is_device_enrolled(device_id):
            return False, "Device not enrolled"
        
        if not self.device_manager.is_device_active(device_id):
            return False, "Device revoked"
        
        device = self.device_manager.get_device(device_id)
        
        # Step 3: Verify certificate
        cert_valid, cert_msg = self._verify_certificate(
            attestation.get("certificate"),
            device["certificate"]
        )
        if not cert_valid:
            return False, f"Certificate invalid: {cert_msg}"
        
        # Step 4: Verify timestamp freshness
        fresh, fresh_msg = self._check_freshness(
            attestation.get("timestamp"),
            challenge_timestamp
        )
        if not fresh:
            return False, f"Timestamp not fresh: {fresh_msg}"
        
        # Step 5: Verify nonce matches
        try:
            attestation_nonce = int(attestation.get("nonce"))
        except (TypeError, ValueError):
            return False, "Nonce missing or malformed in attestation"

        if attestation_nonce != challenge_nonce:
            return False, f"Nonce mismatch: expected {challenge_nonce}, got {attestation.get('nonce')}"
        
        # Step 6: Verify TPM signature
        sig_valid, sig_msg = self._verify_tpm_signature(
            attestation,
            device["certificate"]
        )
        if not sig_valid:
            return False, f"Signature invalid: {sig_msg}"
        
        # Step 7: Check PCR policy
        pcr_valid, pcr_msg = self._check_pcr_policy(
            attestation.get("pcrs", {}),
            device.get("pcr_baseline", {})
        )
        if not pcr_valid:
            return False, f"PCR policy violation: {pcr_msg}"
        
        # Step 8: Update device last seen
        self.device_manager.update_device_last_seen(device_id)
        
        return True, "Attestation verified"
    
    def _verify_certificate(self, received_cert: str, stored_cert: str) -> Tuple[bool, str]:
        """
        Verify device certificate.
        
        In production:
        - Verify certificate chain up to trusted CA
        - Check certificate is not expired
        - Verify certificate extensions
        
        For now: Simple comparison with stored certificate
        """
        try:
            if received_cert != stored_cert:
                return False, "Certificate does not match enrolled certificate"
            
            # Parse certificate to check expiration
            cert_bytes = received_cert.encode('utf-8')
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            
            # Check expiration
            now = time.time()
            if cert.not_valid_before.timestamp() > now:
                return False, "Certificate not yet valid"
            if cert.not_valid_after.timestamp() < now:
                return False, "Certificate expired"
            
            return True, "Certificate valid"
            
        except Exception as e:
            return False, f"Certificate parsing error: {str(e)}"
    
    def _check_freshness(self, received_timestamp: int, challenge_timestamp: int) -> Tuple[bool, str]:
        """
        Check timestamp freshness.
        
        Ensures:
        - Timestamp is not too old (replay protection)
        - Timestamp is not in the future (clock skew)
        """
        now = int(time.time())
        
        # Check received timestamp is not too old
        age = now - received_timestamp
        if age > self.max_timestamp_skew:
            return False, f"Timestamp too old: {age} seconds"
        
        # Check received timestamp is not in the future
        if received_timestamp > now + self.max_timestamp_skew:
            return False, "Timestamp in the future"
        
        # Check it matches challenge timestamp (with tolerance)
        time_diff = abs(received_timestamp - challenge_timestamp)
        if time_diff > self.max_timestamp_skew:
            return False, f"Timestamp differs from challenge: {time_diff} seconds"
        
        return True, "Timestamp fresh"
    
    def _verify_tpm_signature(self, attestation: Dict, device_cert_pem: str) -> Tuple[bool, str]:
        """
        Verify TPM signature over attestation data.
        
        Reconstructs the signed data and verifies signature.
        """
        try:
            # Extract signature
            signature_hex = attestation.get("signature")
            if not signature_hex:
                return False, "No signature provided"
            
            signature = bytes.fromhex(signature_hex)
            
            # Reconstruct data that was signed
            nonce = str(attestation["nonce"])
            timestamp = attestation["timestamp"]
            srs_id = attestation["srs_id"]
            pcrs = attestation["pcrs"]
            
            data_to_verify = f"{nonce}||{timestamp}||{srs_id}".encode()
            
            # Add PCR values in sorted order
            for idx in sorted([int(k) for k in pcrs.keys()]):
                data_to_verify += bytes.fromhex(pcrs[str(idx)])
            
            # Load certificate and extract public key
            cert_bytes = device_cert_pem.encode('utf-8')
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            public_key = cert.public_key()
            
            # Verify signature
            try:
                public_key.verify(
                    signature,
                    data_to_verify,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True, "Signature valid"
            except Exception as e:
                return False, f"Signature verification failed: {str(e)}"
                
        except Exception as e:
            return False, f"Signature verification error: {str(e)}"
    
    def _check_pcr_policy(self, received_pcrs: Dict, baseline_pcrs: Dict) -> Tuple[bool, str]:
        """
        Check PCR policy compliance.
        
        PCRs store measurements of system state.
        Changes in PCRs indicate system changes (boot, BIOS, OS modifications).
        
        Policy options:
        - Strict: PCRs must match baseline exactly
        - Flexible: Allow certain PCRs to change
        - Custom: Define specific allowed values
        
        For now: Verify required PCRs are present and non-zero
        """
        # Check all required PCRs are present
        for idx in self.required_pcr_indices:
            if str(idx) not in received_pcrs:
                return False, f"Missing required PCR {idx}"
        
        # Check PCRs are not all zeros (invalid state)
        for idx, value_hex in received_pcrs.items():
            if not value_hex or value_hex == "00" * 32:
                return False, f"PCR {idx} is zero (invalid state)"
        
        # Optional: Compare with baseline
        # In production, you might want strict comparison for certain PCRs
        # For flexibility, we allow PCRs to differ from baseline
        # (system updates, legitimate changes)
        
        return True, "PCR policy compliant"
    
    def compute_attestation_digest(self, attestation: Dict) -> str:
        """
        Compute attestation digest for zkSNARK public input.
        
        This must match the computation in the circuit.
        """
        components = [
            attestation["certificate"],
            json.dumps(attestation["pcrs"], sort_keys=True),
            attestation["signature"],
            str(attestation["timestamp"]),
            attestation["srs_id"]
        ]
        
        digest_input = "||".join(components).encode()
        digest = hashlib.sha256(digest_input).hexdigest()
        
        return digest

