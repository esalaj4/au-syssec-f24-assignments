import binascii
import json
import math
import secrets
import hashlib
from utils import *

## CONSTANTS
MODULUS_BITS = 3072
SALT_LENGTH = 32

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
    if math.gcd(e, phi) != 1:
        raise ValueError('Chosen e is not relatively prime to phi(n)')

    d = modinv(e, phi)

    # (e, n) - public key ; (d, n) - private key
    return ((e, n), (d, n))


def emsa_pss_encode(message, em_bits):
    m_hash = hashlib.sha256(message).digest()
    hLen = len(m_hash)
    emLen = (em_bits + 7) // 8
    salt = secrets.token_bytes(SALT_LENGTH)
    M = b'\x00' * 8 + m_hash + salt
    H = hashlib.sha256(M).digest()
    PS = b'\x00' * (emLen - SALT_LENGTH - hLen - 2)
    DB = PS + b'\x01' + salt
    dbMask = mgf1(H, emLen - hLen - 1)
    dbMask = bytes(x ^ y for (x, y) in zip(DB, dbMask))
    octets, bits = divmod(8 * emLen - em_bits, 8)
    dbMask = (b'\x00' * octets) + bytes([dbMask[octets] & (255 >> bits)]) + dbMask[octets + 1:]

    EM = dbMask + H + b'\xbc'
    return EM

def sign_message(private_key,message):

    d, N = private_key
    EM = emsa_pss_encode(message, (MODULUS_BITS - 1))
    m = int(binascii.hexlify(EM), 16)
    s = pow(m, d, N)

    return s.to_bytes((s.bit_length() + 7) // 8, 'big')


def emsa_pss_verify(message, em, emBits):
    mHash = hashlib.sha256(message).digest()
    hLen = len(mHash)
    em_len = -(-emBits // 8)
    maskedDB, h = em[:em_len - hLen - 1], em[em_len - hLen - 1:-1]
    octets, bits = divmod((8 * em_len - emBits), 8)

    db_mask = mgf1(h, em_len - hLen - 1)

    # Unmask maskedDB
    db = bytes(x ^ y for x, y in zip(maskedDB, db_mask))

    # Adjust the last byte of db
    new_byte = bytes([db[octets] & (255 >> bits)])
    db = (b'\x00' * octets) + new_byte + db[octets + 1:]
    salt = db[-SALT_LENGTH:]
    m_prime = (b'\x00' * 8) + mHash + salt
    h_prime = hashlib.sha256(m_prime).digest()
    result = all(x == y for x, y in zip(h_prime, h))

    return result


def verify_signature(public_key, message, signature):
    e, n = public_key
    embits = MODULUS_BITS - 1
    if(len(signature) != 128 * 3):
        return False
    s = int(binascii.hexlify(signature), 16)
    m = pow(s, e, n)
    EM = m.to_bytes((m.bit_length() + 7) // 8, 'big')

    try:
        is_valid = emsa_pss_verify(message, EM, embits)
        return is_valid
    except ValueError:
        return False


public_key, private_key = generate_rsa_keys()
print("\nPublic key:", public_key)
print("\nPrivate key:", private_key)
msg = f'Hello crypto'.encode()
# sign the message
signature = sign_message(private_key,msg)
#print(signature)
#print("verify")
verified = verify_signature(public_key,msg, signature)

print(f"Message Verified: {verified}")
print("Altering message to 'Hello crypto!'")
msg = f'Hello crypto!'.encode()
verified = verify_signature(public_key, msg, signature)
print(f'Message Verified: {verified}')
