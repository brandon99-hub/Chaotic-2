"""
Transparency Ledger for audit trail.
Records SRS ceremonies, device enrollments, and authentication events.
"""

import json
import time
import hashlib
from typing import Dict, List
from pathlib import Path


class TransparencyLedger:
    """
    Append-only ledger for transparency and audit.
    
    Records:
    - SRS ceremony events
    - Device enrollments
    - Authentication attempts
    - Attestation verifications
    """
    
    def __init__(self, ledger_path: str = "transparency_ledger.jsonl"):
        """
        Initialize transparency ledger.
        
        Args:
            ledger_path: Path to ledger file (JSON Lines format)
        """
        self.ledger_path = Path(ledger_path)
        self._ensure_ledger_exists()
    
    def _ensure_ledger_exists(self):
        """Create ledger file if it doesn't exist."""
        if not self.ledger_path.exists():
            self.ledger_path.touch()
            print(f"[Ledger] Created new ledger: {self.ledger_path}")
    
    def append_entry(self, event_type: str, data: Dict) -> str:
        """
        Append entry to ledger.
        
        Args:
            event_type: Type of event (srs_ceremony, device_enrollment, auth_attempt, etc.)
            data: Event data
        
        Returns:
            Entry hash (for reference)
        """
        entry = {
            "timestamp": int(time.time()),
            "event_type": event_type,
            "data": data
        }
        
        # Compute entry hash
        entry_json = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()
        entry["entry_hash"] = entry_hash
        
        # Append to ledger (JSON Lines format)
        with open(self.ledger_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
        
        return entry_hash
    
    def log_srs_ceremony(self, srs_id: str, participants: List[str], transcript_hash: str):
        """Log SRS ceremony event."""
        return self.append_entry("srs_ceremony", {
            "srs_id": srs_id,
            "participants": participants,
            "transcript_hash": transcript_hash
        })
    
    def log_device_enrollment(self, device_id: str, user_id: str, cert_hash: str):
        """Log device enrollment event."""
        return self.append_entry("device_enrollment", {
            "device_id": device_id,
            "user_id": user_id,
            "cert_hash": cert_hash
        })
    
    def log_auth_attempt(
        self,
        user_id: str,
        device_id: str,
        success: bool,
        attestation_digest: str,
        proof_hash: str,
        srs_id: str
    ):
        """Log authentication attempt."""
        return self.append_entry("auth_attempt", {
            "user_id": user_id,
            "device_id": device_id,
            "success": success,
            "attestation_digest": attestation_digest,
            "proof_hash": proof_hash,
            "srs_id": srs_id
        })
    
    def log_device_revocation(self, device_id: str, reason: str):
        """Log device revocation."""
        return self.append_entry("device_revocation", {
            "device_id": device_id,
            "reason": reason
        })
    
    def get_recent_entries(self, count: int = 100, event_type: str = None) -> List[Dict]:
        """
        Get recent ledger entries.
        
        Args:
            count: Number of entries to retrieve
            event_type: Filter by event type (optional)
        
        Returns:
            List of entries
        """
        entries = []
        
        if not self.ledger_path.exists():
            return entries
        
        with open(self.ledger_path, 'r') as f:
            lines = f.readlines()
        
        # Read from end
        for line in reversed(lines[-count:]):
            if line.strip():
                entry = json.loads(line)
                if event_type is None or entry["event_type"] == event_type:
                    entries.append(entry)
        
        return entries
    
    def get_user_auth_history(self, user_id: str, limit: int = 50) -> List[Dict]:
        """Get authentication history for a user."""
        all_entries = self.get_recent_entries(count=1000, event_type="auth_attempt")
        user_entries = [
            entry for entry in all_entries
            if entry["data"]["user_id"] == user_id
        ]
        return user_entries[:limit]
    
    def get_device_history(self, device_id: str) -> List[Dict]:
        """Get all events for a device."""
        all_entries = []
        
        if not self.ledger_path.exists():
            return all_entries
        
        with open(self.ledger_path, 'r') as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    data = entry.get("data", {})
                    if data.get("device_id") == device_id:
                        all_entries.append(entry)
        
        return all_entries
    
    def verify_ledger_integrity(self) -> bool:
        """
        Verify ledger integrity by recomputing entry hashes.
        
        Returns:
            True if all hashes are valid
        """
        if not self.ledger_path.exists():
            return True
        
        with open(self.ledger_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                
                entry = json.loads(line)
                stored_hash = entry.pop("entry_hash", None)
                
                # Recompute hash
                entry_json = json.dumps(entry, sort_keys=True)
                computed_hash = hashlib.sha256(entry_json.encode()).hexdigest()
                
                if stored_hash != computed_hash:
                    print(f"[Ledger] Integrity violation at line {line_num}")
                    return False
        
        return True
    
    def get_stats(self) -> Dict:
        """Get ledger statistics."""
        stats = {
            "total_entries": 0,
            "event_types": {},
            "first_entry_time": None,
            "last_entry_time": None
        }
        
        if not self.ledger_path.exists():
            return stats
        
        with open(self.ledger_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                entry = json.loads(line)
                stats["total_entries"] += 1
                
                event_type = entry["event_type"]
                stats["event_types"][event_type] = stats["event_types"].get(event_type, 0) + 1
                
                timestamp = entry["timestamp"]
                if stats["first_entry_time"] is None:
                    stats["first_entry_time"] = timestamp
                stats["last_entry_time"] = timestamp
        
        return stats

