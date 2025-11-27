"""
SRS (Structured Reference String) Manager
Manages zkSNARK trusted setup ceremonies with attestation tracking.
"""

import json
import hashlib
import time
from typing import Dict, List, Optional
from pathlib import Path


class SRSManager:
    """
    Manages SRS lifecycle for zkSNARK system.
    
    Responsibilities:
    - Track active SRS ceremonies
    - Validate SRS IDs
    - Support SRS rotation
    - Link to transparency ledger for audit
    """
    
    def __init__(self, storage_path: str = "srs_registry.json"):
        """
        Initialize SRS manager.
        
        Args:
            storage_path: Path to store SRS registry
        """
        self.storage_path = Path(storage_path)
        self.srs_registry = self._load_registry()
        self._ensure_default_srs()
    
    def _load_registry(self) -> Dict:
        """Load SRS registry from disk."""
        if self.storage_path.exists():
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_registry(self):
        """Save SRS registry to disk."""
        with open(self.storage_path, 'w') as f:
            json.dump(self.srs_registry, f, indent=2)
    
    def _ensure_default_srs(self):
        """Ensure a default SRS exists for development."""
        if "default_srs_v1" not in self.srs_registry:
            self.register_srs(
                srs_id="default_srs_v1",
                ceremony_transcript="Development SRS - Not for production",
                participants=[],
                proving_key_path="keys/auth_proving_key.zkey",
                verification_key_path="keys/auth_verification_key.json"
            )
    
    def register_srs(
        self,
        srs_id: str,
        ceremony_transcript: str,
        participants: List[str],
        proving_key_path: str,
        verification_key_path: str,
        attestation_hashes: Optional[List[str]] = None
    ) -> Dict:
        """
        Register a new SRS from a ceremony.
        
        Args:
            srs_id: Unique identifier for this SRS
            ceremony_transcript: Description or hash of ceremony
            participants: List of participant IDs
            proving_key_path: Path to proving key file
            verification_key_path: Path to verification key file
            attestation_hashes: Hashes of participant attestations
        
        Returns:
            SRS record
        """
        if srs_id in self.srs_registry:
            raise ValueError(f"SRS ID {srs_id} already exists")
        
        srs_record = {
            "srs_id": srs_id,
            "created_at": int(time.time()),
            "ceremony_transcript": ceremony_transcript,
            "participants": participants,
            "participant_count": len(participants),
            "proving_key_path": proving_key_path,
            "verification_key_path": verification_key_path,
            "attestation_hashes": attestation_hashes or [],
            "status": "active",
            "deprecated_at": None
        }
        
        self.srs_registry[srs_id] = srs_record
        self._save_registry()
        
        print(f"[SRS] Registered new SRS: {srs_id}")
        return srs_record
    
    def get_srs(self, srs_id: str) -> Optional[Dict]:
        """Get SRS information."""
        return self.srs_registry.get(srs_id)
    
    def is_srs_valid(self, srs_id: str) -> bool:
        """Check if SRS is valid and active."""
        srs = self.srs_registry.get(srs_id)
        return srs is not None and srs["status"] == "active"
    
    def get_active_srs_list(self) -> List[str]:
        """Get list of active SRS IDs."""
        return [
            srs_id for srs_id, srs in self.srs_registry.items()
            if srs["status"] == "active"
        ]
    
    def deprecate_srs(self, srs_id: str, reason: str = "Rotated"):
        """
        Deprecate an SRS (for rotation).
        
        Args:
            srs_id: SRS to deprecate
            reason: Deprecation reason
        """
        if srs_id in self.srs_registry:
            self.srs_registry[srs_id]["status"] = "deprecated"
            self.srs_registry[srs_id]["deprecated_at"] = int(time.time())
            self.srs_registry[srs_id]["deprecation_reason"] = reason
            self._save_registry()
            print(f"[SRS] Deprecated SRS {srs_id}: {reason}")
    
    def get_default_srs_id(self) -> str:
        """Get the default SRS ID."""
        # Return the most recent active SRS
        active_srs = [
            (srs_id, srs) for srs_id, srs in self.srs_registry.items()
            if srs["status"] == "active"
        ]
        
        if not active_srs:
            raise ValueError("No active SRS available")
        
        # Sort by creation time, return newest
        active_srs.sort(key=lambda x: x[1]["created_at"], reverse=True)
        return active_srs[0][0]
    
    def get_proving_key_path(self, srs_id: str) -> Optional[str]:
        """Get proving key path for SRS."""
        srs = self.srs_registry.get(srs_id)
        return srs["proving_key_path"] if srs else None
    
    def get_verification_key_path(self, srs_id: str) -> Optional[str]:
        """Get verification key path for SRS."""
        srs = self.srs_registry.get(srs_id)
        return srs["verification_key_path"] if srs else None
    
    def get_srs_stats(self) -> Dict:
        """Get SRS statistics."""
        total = len(self.srs_registry)
        active = sum(1 for srs in self.srs_registry.values() if srs["status"] == "active")
        deprecated = sum(1 for srs in self.srs_registry.values() if srs["status"] == "deprecated")
        
        return {
            "total_srs": total,
            "active_srs": active,
            "deprecated_srs": deprecated
        }

