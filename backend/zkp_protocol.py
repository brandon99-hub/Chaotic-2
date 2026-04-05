from chaotic_generator import ChaoticGenerator
from hash_utils import (
    SNARK_FIELD_MODULUS,
    compute_commitment,
    hash_password_to_field,
    reduce_to_field,
)
from zksnark_utils import generate_proof, verify_proof, ZkSnarkDependencyError
import db_store


class Server:
    def __init__(self):
        self.chaotic_gen = ChaoticGenerator()

    # Expose a users-like count property for health checks
    @property
    def users(self):
        """Proxy to DB so health-check len(server_instance.users) works."""
        return {hr_id: {} for hr_id in db_store.list_users()}

    def get_random_g0(self):
        random_value = self.chaotic_gen.get_random_value(1000, 10**6)
        return reduce_to_field(random_value)

    def register_user(self, hr_id, Y, g0):
        Y = reduce_to_field(Y)
        g0 = reduce_to_field(g0)
        if db_store.user_exists(hr_id):
            return False, "User already exists"
        db_store.save_user(hr_id, Y, g0)
        return True, "User registered successfully"

    def authenticate_user(self, hr_id, proof, public_signals):
        user_data = db_store.get_user(hr_id)
        if not user_data:
            return False, "User not found"

        expected_g0 = str(user_data["g0"])
        expected_Y = str(user_data["Y"])

        if len(public_signals) < 2:
            return False, "Invalid public signal set"

        print(f"[DEBUG] Expected g0: {expected_g0}")
        print(f"[DEBUG] Received g0: {public_signals[0]}")
        print(f"[DEBUG] Expected Y:  {expected_Y}")
        print(f"[DEBUG] Received Y:  {public_signals[1]}")

        if public_signals[0] != expected_g0 or public_signals[1] != expected_Y:
            return False, "Public signals do not match stored commitment"

        is_valid = verify_proof(proof, public_signals)
        if is_valid:
            return True, "Authentication verified"
        return False, "Authentication failed"


class Client:
    def __init__(self):
        self.chaotic_gen = ChaoticGenerator()
        self.g0 = None
        self.commitment = None

    def register(self, hr_id, password, g0):
        self.g0 = reduce_to_field(g0)
        secret_x = hash_password_to_field(password)
        self.commitment = compute_commitment(self.g0, secret_x)
        return {
            "hr_id": hr_id,
            "Y": self.commitment,
            "g0": self.g0,
        }

    def login(self, hr_id, password):
        if self.g0 is None:
            raise ValueError("Client must register before login to receive g0")
        if self.commitment is None:
            raise ValueError("Client must register before login to receive commitment")

        secret_x = hash_password_to_field(password)

        print(f"[DEBUG CLIENT] g0 to prove: {self.g0}")
        print(f"[DEBUG CLIENT] X (hashed pw): {secret_x}")
        print(f"[DEBUG CLIENT] Y (commitment): {self.commitment}")
        print(f"[DEBUG CLIENT] Expected g0*X: {compute_commitment(self.g0, secret_x)}")

        try:
            proof, public_signals = generate_proof(self.g0, secret_x, self.commitment)
        except ZkSnarkDependencyError as exc:
            raise RuntimeError(str(exc)) from exc

        print(f"[DEBUG CLIENT] Proof public signals: {public_signals}")

        return {
            "hr_id": hr_id,
            "proof": proof,
            "public_signals": public_signals,
        }
