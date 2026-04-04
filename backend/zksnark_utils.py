import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple
import shutil

# On Windows, just use "snarkjs" and let shell find it
# On Unix, try to find the full path
if sys.platform == "win32":
    _snarkjs_default = "snarkjs"
else:
    _snarkjs_default = shutil.which("snarkjs") or "snarkjs"

SNARKJS_CMD = os.environ.get("SNARKJS_PATH", _snarkjs_default)
DEFAULT_BUILD_DIR = Path("build")
DEFAULT_KEYS_DIR = Path("keys")
CIRCUIT_NAME = "auth"

WASM_PATH = DEFAULT_BUILD_DIR / f"{CIRCUIT_NAME}_js" / f"{CIRCUIT_NAME}.wasm"
ZKEY_PATH = DEFAULT_KEYS_DIR / f"{CIRCUIT_NAME}_proving_key.zkey"
VERIFICATION_KEY_PATH = DEFAULT_KEYS_DIR / f"{CIRCUIT_NAME}_verification_key.json"


class ZkSnarkDependencyError(RuntimeError):
    """Raised when required zkSNARK tooling or artifacts are missing."""


def _check_artifacts() -> None:
    missing = []
    for path in (WASM_PATH, ZKEY_PATH, VERIFICATION_KEY_PATH):
        if not Path(path).exists():
            missing.append(str(path))
    if missing:
        raise ZkSnarkDependencyError(
            "Missing zkSNARK artifacts. Run 'pwsh scripts/setup_snark.ps1' first. "
            f"Missing: {', '.join(missing)}"
        )

    try:
        use_shell = sys.platform == "win32"
        result = subprocess.run([SNARKJS_CMD, "--version"], capture_output=True, shell=use_shell)
        # snarkjs returns non-zero exit code even for --version, so just check it ran
        if result.returncode > 100 or (result.returncode != 0 and not result.stdout):
            raise subprocess.CalledProcessError(result.returncode, SNARKJS_CMD)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise ZkSnarkDependencyError(
            f"snarkjs CLI not available at '{SNARKJS_CMD}'. Install via 'npm install -g snarkjs' "
            "and ensure it's on PATH or set SNARKJS_PATH."
        ) from exc


def _run_snarkjs(args: List[str]) -> subprocess.CompletedProcess:
    # On Windows, use shell=True to properly execute .cmd files
    use_shell = sys.platform == "win32"
    result = subprocess.run(args, capture_output=True, text=True, shell=use_shell)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command {' '.join(args)} failed with code {result.returncode}:\n{result.stderr}"
        )
    return result


def generate_proof(g0: int, secret_x: int, commitment_y: int) -> Tuple[Dict, List[str]]:
    """
    Generate a Groth16 proof using snarkjs for the relation Poseidon(g0, X) = Y.

    Returns a tuple of (proof_json, public_signals).
    """
    _check_artifacts()

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        input_json = temp_path / "input.json"
        witness_wtns = temp_path / "witness.wtns"
        proof_json = temp_path / "proof.json"
        public_json = temp_path / "public.json"

        input_payload = {
            "g0": str(int(g0)),
            "Y": str(int(commitment_y)),
            "X": str(int(secret_x)),
        }
        print(f"[DEBUG SNARK] Input payload: {input_payload}")
        input_json.write_text(json.dumps(input_payload), encoding="utf-8")

        _run_snarkjs([
            SNARKJS_CMD,
            "wtns",
            "calculate",
            str(WASM_PATH),
            str(input_json),
            str(witness_wtns),
        ])

        _run_snarkjs([
            SNARKJS_CMD,
            "groth16",
            "prove",
            str(ZKEY_PATH),
            str(witness_wtns),
            str(proof_json),
            str(public_json),
        ])

        proof = json.loads(proof_json.read_text(encoding="utf-8"))
        public_signals = json.loads(public_json.read_text(encoding="utf-8"))
        
        print(f"[DEBUG SNARK] Public signals from proof: {public_signals}")

    return proof, public_signals


def verify_proof(proof: Dict, public_signals: List[str]) -> bool:
    """Verify a Groth16 proof using snarkjs verify command."""
    _check_artifacts()

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        proof_json = temp_path / "proof.json"
        public_json = temp_path / "public.json"

        proof_json.write_text(json.dumps(proof), encoding="utf-8")
        public_json.write_text(json.dumps(public_signals), encoding="utf-8")

        try:
            _run_snarkjs([
                SNARKJS_CMD,
                "groth16",
                "verify",
                str(VERIFICATION_KEY_PATH),
                str(public_json),
                str(proof_json),
            ])
        except RuntimeError:
            return False
    return True
