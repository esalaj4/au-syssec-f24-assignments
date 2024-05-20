import hashlib
from task3_utils import *


# Generate RSA keys
def generate_rsa_keys():
    bit_length = 3072
    prime_number_bits = bit_length // 2
    e = 65537

    # Ensure p and q are distinct primes
    while True:
        p = generate_prime_number(prime_number_bits)
        q = generate_prime_number(prime_number_bits)
        if p != q:
            break

    n = p * q
    phi = (p - 1) * (q - 1)

    # Ensure e is relatively prime to phi
    if gcd(e, phi) != 1:
        raise ValueError('Chosen e is not relatively prime to phi(n)')

    d = mod_inverse(e, phi)

    # (e, n) - public key ; (d, n) - private key
    return ((e, n), (d, n))

# Sign a message using RSA-PSS
def sign_message(private_key, message, s_len=32):
    m_hash = hashlib.sha256(message).digest()
    mod_bits = private_key[1].bit_length()
    em = emsa_pss_encode(m_hash, mod_bits - 1, s_len=s_len, hash_class=hashlib.sha256)
    m_int = bytes_to_int(em)
    n, d = private_key
    s_int = pow(m_int, d, n)
    return int_to_bytes(s_int)

# Signature verification
def verify_signature(public_key, message, signature, s_len=32):
    s_int = bytes_to_int(signature)
    e, n = public_key
    m_int = pow(s_int, e, n)
    EM = int_to_bytes(m_int)
    try:
        is_valid = emsa_pss_verify(message, EM, n.bit_length() - 1, s_len=s_len, hash_class=hashlib.sha256)
        return is_valid
    except ValueError:
        return False


public_key, private_key = generate_rsa_keys()
print("\nPublic key:", public_key)
print("\nPrivate key:", private_key)
message = b"Hello crypto!"
signature = sign_message(private_key, message)
print("\nSignature:", signature.hex())
is_valid = verify_signature(public_key, message, signature)
print("\nSignature valid:", is_valid)
