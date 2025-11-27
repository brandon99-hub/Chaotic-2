"""
Windows TPM 2.0 integration utilities.
Falls back to software keys when hardware is unavailable.
"""

import base64
import datetime
import hashlib
import json
import subprocess
import sys
from typing import Dict, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


class TPMManager:
    """
    Manages TPM operations for device enrollment and attestation.

    Windows implementation relies on PowerShell to provision
    TPM-backed certificates via the Microsoft Platform Crypto Provider.
    """

    def __init__(self):
        self.device_state: Dict[str, Dict] = {}
        self.platform_info = {
            "tpm_present": False,
            "tpm_ready": False,
            "manufacturer": None,
            "version": None,
            "mode": "software",
        }
        self.tpm_available = False
        self.tpm_mode = "software"

        if sys.platform == "win32":
            self._init_windows_support()
        else:
            print("[TPM] Non-Windows platform detected, using software fallback")

        if not self.tpm_available:
            print("[TPM] Using software fallback mode")

    # ------------------------------------------------------------------
    # Windows helper routines
    # ------------------------------------------------------------------

    def _run_powershell(self, script: str) -> str:
        """Execute PowerShell and return stdout (raises on failure)."""
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            raise RuntimeError(stderr or "PowerShell command failed")
        return completed.stdout.strip()

    def _init_windows_support(self):
        try:
            script = "Get-Tpm | ConvertTo-Json -Depth 2"
            tpm_json = self._run_powershell(script)
            info = json.loads(tpm_json) if tpm_json else {}
            self.platform_info.update(
                {
                    "tpm_present": info.get("TpmPresent", False),
                    "tpm_ready": info.get("TpmReady", False),
                    "manufacturer": info.get("ManufacturerIdTxt"),
                    "version": info.get("ManufacturerVersion"),
                    "mode": "windows",
                }
            )
            if info.get("TpmPresent") and info.get("TpmReady"):
                self.tpm_available = True
                self.tpm_mode = "windows"
                print(
                    f"[TPM] Windows TPM detected ({self.platform_info['manufacturer']} "
                    f"{self.platform_info['version']})"
                )
            else:
                print("[TPM] Windows TPM not ready, falling back to software")
        except Exception as exc:
            print(f"[TPM] Failed to query Windows TPM status: {exc}")
            self.tpm_available = False
            self.tpm_mode = "software"

    def _ensure_windows_certificate(self, subject: str) -> Dict[str, str]:
        """
        Ensure a TPM-backed certificate exists for the subject.
        Returns {"thumbprint": ..., "certificate_pem": ...}
        """
        subject_ps = subject.replace("'", "''")
        script = f"""
$subject = '{subject_ps}';
$store = Get-ChildItem -Path 'Cert:\\CurrentUser\\My' | Where-Object {{ $_.Subject -eq $subject }};
if (-not $store) {{
    $store = New-SelfSignedCertificate `
        -Subject $subject `
        -CertStoreLocation 'Cert:\\CurrentUser\\My' `
        -KeyStorageProvider 'Microsoft Platform Crypto Provider' `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -KeyExportPolicy NonExportable `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddYears(3);
}}
if ($store -is [System.Array]) {{ $cert = $store[0]; }} else {{ $cert = $store; }}
$bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert);
$base64 = [System.Convert]::ToBase64String($bytes);
Write-Output ($cert.Thumbprint + '|' + $base64);
""".strip()

        output = self._run_powershell(script)
        thumb, b64_cert = output.split("|", 1)

        # PowerShell can emit newline/whitespace characters inside the base64 blob.
        # Strip them out so Python's decoder always sees clean DER bytes.
        b64_cert = "".join(b64_cert.split())

        try:
            cert_der = base64.b64decode(b64_cert, validate=True)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to decode TPM certificate from PowerShell output ({exc})"
            )

        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
        cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM).decode()
        return {"thumbprint": thumb.strip(), "certificate_pem": cert_pem}

    def _sign_with_windows_cert(self, thumbprint: str, data: bytes) -> bytes:
        """Sign data using the TPM-backed certificate via PowerShell/RSACng."""
        thumb_ps = thumbprint.replace("'", "''")
        data_b64 = base64.b64encode(data).decode()
        script = f"""
$thumb = '{thumb_ps}';
$data = [System.Convert]::FromBase64String('{data_b64}');
$cert = Get-Item -Path ('Cert:\\CurrentUser\\My\\' + $thumb) -ErrorAction Stop;
$privateKey = $cert.GetRSAPrivateKey();
$signature = $privateKey.SignData(
    $data,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
);
[System.Convert]::ToBase64String($signature);
""".strip()

        output = self._run_powershell(script)
        return base64.b64decode(output)

    # ------------------------------------------------------------------
    # Device enrollment helpers
    # ------------------------------------------------------------------

    def _create_software_profile(self, device_id: str) -> Dict:
        """Create RSA key + certificate in software fallback mode."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Software"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "DevMode"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "zkSNARK-Auth-Dev"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"Device-{device_id}"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        private_pem = (
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )

        return {
            "mode": "software",
            "certificate": cert_pem,
            "key_storage": {"private_key_pem": private_pem},
            "tpm_info": self.platform_info,
        }

    def _create_windows_profile(self, device_id: str) -> Dict:
        """Provision a TPM-backed certificate for the device."""
        subject = f"CN=zkSNARK-{device_id}"
        cert_data = self._ensure_windows_certificate(subject)
        return {
            "mode": "windows",
            "certificate": cert_data["certificate_pem"],
            "cert_thumbprint": cert_data["thumbprint"],
            "tpm_info": self.platform_info,
        }

    def generate_device_key(self, device_id: str) -> Dict:
        """
        Provision a device key/certificate.
        Returns metadata that must be persisted alongside the device record.
        """
        if self.tpm_available and self.tpm_mode == "windows":
            try:
                profile = self._create_windows_profile(device_id)
                print(f"[TPM] Provisioned TPM-backed certificate for {device_id}")
                return profile
            except Exception as exc:
                print(f"[TPM] Windows TPM provisioning failed: {exc}")
                print("[TPM] Falling back to software keys for this device")

        return self._create_software_profile(device_id)

    # ------------------------------------------------------------------
    # Attestation helpers
    # ------------------------------------------------------------------

    def read_pcrs(self, pcr_indices: Optional[list] = None) -> Dict[int, bytes]:
        """Return PCR measurements (simulated for now)."""
        if pcr_indices is None:
            pcr_indices = [0, 1, 2, 3, 7]

        pcrs: Dict[int, bytes] = {}

        if self.tpm_mode == "windows" and self.tpm_available:
            for idx in pcr_indices:
                pcrs[idx] = hashlib.sha256(f"PCR{idx}_windows_real".encode()).digest()
        elif self.tpm_mode == "linux" and self.tpm_available:
            for idx in pcr_indices:
                pcrs[idx] = hashlib.sha256(f"PCR{idx}_linux".encode()).digest()
        else:
            for idx in pcr_indices:
                pcrs[idx] = hashlib.sha256(f"PCR{idx}_software".encode()).digest()

        return pcrs

    def _sign_with_software_key(self, key_pem: str, data: bytes) -> bytes:
        """Sign using stored software fallback key."""
        private_key = serialization.load_pem_private_key(
            key_pem.encode(), password=None, backend=default_backend()
        )
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def sign_data(self, device_record: Dict, data: bytes) -> bytes:
        """Sign arbitrary data with the device's key material."""
        mode = (
            device_record.get("tpm_mode")
            or device_record.get("tpm_info", {}).get("mode")
            or self.tpm_mode
        )

        if mode == "windows" and device_record.get("cert_thumbprint"):
            return self._sign_with_windows_cert(
                device_record["cert_thumbprint"], data
            )

        key_storage = device_record.get("key_storage", {})
        private_key_pem = key_storage.get("private_key_pem")
        if private_key_pem:
            return self._sign_with_software_key(private_key_pem, data)

        raise RuntimeError("No signing material available for device")

    def get_attestation_quote(
        self,
        device_record: Dict,
        nonce: int,
        timestamp: int,
        srs_id: str,
    ) -> Dict:
        """Build attestation object for a specific device."""
        pcrs = self.read_pcrs()

        data_to_sign = f"{nonce}||{timestamp}||{srs_id}".encode()
        for idx in sorted(pcrs.keys()):
            data_to_sign += pcrs[idx]

        signature = self.sign_data(device_record, data_to_sign)

        attestation = {
            "signature": signature.hex(),
            "pcrs": {str(k): v.hex() for k, v in pcrs.items()},
            "certificate": device_record["certificate"],
            # Represent nonce as string to avoid precision loss in JS clients
            "nonce": str(nonce),
            "timestamp": timestamp,
            "srs_id": srs_id,
            "tpm_mode": device_record.get("tpm_mode", self.tpm_mode),
        }
        return attestation

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def compute_attestation_digest(self, attestation: Dict) -> str:
        components = [
            attestation["certificate"],
            json.dumps(attestation["pcrs"], sort_keys=True),
            attestation["signature"],
            str(attestation["timestamp"]),
            attestation["srs_id"],
        ]
        digest_input = "||".join(components).encode()
        return hashlib.sha256(digest_input).hexdigest()

    def get_tpm_info(self) -> Dict:
        return {
            "tpm_available": self.tpm_available,
            "mode": self.tpm_mode,
            "platform": sys.platform,
            **self.platform_info,
        }


_tpm_manager_instance: Optional[TPMManager] = None


def get_tpm_manager() -> TPMManager:
    global _tpm_manager_instance
    if _tpm_manager_instance is None:
        _tpm_manager_instance = TPMManager()
    return _tpm_manager_instance
