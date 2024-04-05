from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os


if __name__ == '__main__':
    # Generate a random 16-byte IV
    iv = os.urandom(16)
    print(f"IV: {iv.hex()}")

    passphrase = b"I-lov3-systems-security-course" 
    salt = os.urandom(16) 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
    )
    derived_key = kdf.derive(passphrase)
    print(f"Derived AES Key: {derived_key.hex()}")
