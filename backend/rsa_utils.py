from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os


class RSAKeyPair:
    def __init__(self, key_size=2048):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def get_public_key_numbers(self):
        public_numbers = self.public_key.public_numbers()
        return public_numbers.n, public_numbers.e
    
    def get_private_key_numbers(self):
        private_numbers = self.private_key.private_numbers()
        return private_numbers.d, private_numbers.public_numbers.n
    
    def encrypt(self, message_bytes):
        ciphertext = self.public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def decrypt(self, ciphertext):
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    def encrypt_number(self, number):
        message_bytes = number.to_bytes((number.bit_length() + 7) // 8, 'big')
        ciphertext = self.encrypt(message_bytes)
        return int.from_bytes(ciphertext, 'big')
    
    def decrypt_number(self, ciphertext_int):
        ciphertext_bytes = ciphertext_int.to_bytes((ciphertext_int.bit_length() + 7) // 8, 'big')
        plaintext_bytes = self.decrypt(ciphertext_bytes)
        return int.from_bytes(plaintext_bytes, 'big')


def rsa_modular_exponentiation(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result


if __name__ == "__main__":
    keypair = RSAKeyPair()
    n, e = keypair.get_public_key_numbers()
    d, _ = keypair.get_private_key_numbers()
    
    print(f"RSA Key Pair Generated:")
    print(f"n (modulus): {n}")
    print(f"e (public exponent): {e}")
    print(f"d (private exponent): {d}")
    
    test_message = 12345
    encrypted = keypair.encrypt_number(test_message)
    decrypted = keypair.decrypt_number(encrypted)
    
    print(f"\nTest encryption/decryption:")
    print(f"Original: {test_message}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_message == decrypted}")

