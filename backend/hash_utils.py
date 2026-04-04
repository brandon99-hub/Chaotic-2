import hashlib

SNARK_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def hash_string(text, algorithm='sha256'):
    if algorithm == 'sha256':
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(text.encode('utf-8')).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def hash_to_int(text, algorithm='sha256', mod=None):
    hash_hex = hash_string(text, algorithm)
    hash_int = int(hash_hex, 16)
    if mod:
        return hash_int % mod
    return hash_int


def reduce_to_field(value, modulus=SNARK_FIELD_MODULUS):
    return int(value) % modulus


def hash_password_to_field(password: str) -> int:
    """Hash a password to a field element compatible with the SNARK field."""
    return hash_to_int(password, mod=SNARK_FIELD_MODULUS)


def compute_commitment(g0: int, secret_x: int, modulus: int = SNARK_FIELD_MODULUS) -> int:
    """Compute the public commitment Y = g0 * X mod field."""
    return (int(g0) % modulus) * (int(secret_x) % modulus) % modulus


def fast_exponentiation(base, exponent, modulus):
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result


def combine_hash(*values):
    combined = ''.join(str(v) for v in values)
    return hash_string(combined)


def hash_for_zkp(Y, m, a):
    return hash_to_int(combine_hash(Y, m, a))


if __name__ == "__main__":
    test_text = "test_password"
    hashed = hash_string(test_text)
    print(f"Hash of '{test_text}': {hashed}")
    
    hash_int = hash_to_int(test_text)
    print(f"Hash as integer: {hash_int}")
    
    base = 5
    exp = 123
    mod = 1000
    result = fast_exponentiation(base, exp, mod)
    print(f"{base}^{exp} mod {mod} = {result}")

