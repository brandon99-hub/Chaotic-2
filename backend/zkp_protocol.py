from chaotic_generator import ChaoticGenerator
from hash_utils import (
    SNARK_FIELD_MODULUS,
    compute_commitment,
    hash_password_to_field,
    reduce_to_field,
)
from zksnark_utils import generate_proof, verify_proof, ZkSnarkDependencyError


class Server:
    def __init__(self):
        self.users = {}
        self.chaotic_gen = ChaoticGenerator()

    def get_random_g0(self):
        random_value = self.chaotic_gen.get_random_value(1000, 10**6)
        return reduce_to_field(random_value)

    def register_user(self, hr_id, Y, g0):
        if hr_id in self.users:
            return False, "User already exists"
        self.users[hr_id] = {
            "Y": reduce_to_field(Y),
            "g0": reduce_to_field(g0),
        }
        return True, "User registered successfully"

    def authenticate_user(self, hr_id, proof, public_signals):
        if hr_id not in self.users:
            return False, "User not found"

        user_data = self.users[hr_id]
        expected_g0 = str(user_data["g0"])
        expected_Y = str(user_data["Y"])

        if len(public_signals) < 2:
            return False, "Invalid public signal set"

        # DEBUG: Print what we're comparing
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
        
        # DEBUG: Print what we're sending to proof generation
        print(f"[DEBUG CLIENT] g0 to prove: {self.g0}")
        print(f"[DEBUG CLIENT] X (hashed pw): {secret_x}")
        print(f"[DEBUG CLIENT] Y (commitment): {self.commitment}")
        print(f"[DEBUG CLIENT] Expected g0*X: {compute_commitment(self.g0, secret_x)}")
        
        # Use the stored commitment (Y) from registration, not a freshly computed one
        # The zkSNARK circuit will verify that g0 * X == Y
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

