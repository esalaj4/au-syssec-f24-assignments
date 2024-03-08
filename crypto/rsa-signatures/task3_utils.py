import random
import hashlib
import os

def modinv(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception()
    else:
        return x % m

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = extended_gcd(b % a, a)
        return (g, y - (b // a) * x, x)

def is_prime(n, k=128):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    d = n - 1
    while d % 2 == 0:
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        while d != n - 1:
            x = (x * x) % n
            d *= 2

            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_candidate(n):
    p = random.getrandbits(n)
    p |= (1 << n - 1) | 1
    return p

def generate_prime_number(n):
    p = generate_prime_candidate(n)
    while not is_prime(p, 128):
        p = generate_prime_candidate(n)
    return p

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

# Mask Generation Function based on a hash function (MGF1)
def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha256):
    t = b""
    for counter in range(0, (mask_len // hash_class().digest_size) + 1):
        C = counter.to_bytes(4, 'big')
        t += hash_class(mgf_seed + C).digest()
    return t[:mask_len]

# EMSA-PSS Encode function as per RFC 8017
def emsa_pss_encode(M, em_bits, s_len=32, hash_class=hashlib.sha256):
    m_hash = hash_class(M).digest()
    em_len = (em_bits + 7) // 8
    if em_len < hash_class().digest_size + s_len + 2:
        raise ValueError()

    salt = os.urandom(s_len)
    M_prime = b'\x00' * 8 + m_hash + salt
    H = hash_class(M_prime).digest()
    PS = b'\x00' * (em_len - s_len - hash_class().digest_size - 2)
    DB = PS + b'\x01' + salt
    dbMask = mgf1(H, em_len - hash_class().digest_size - 1, hash_class)
    maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
    maskedDB = maskedDB[0:-(em_bits // 8)] + b'\x00' + maskedDB[-(em_bits // 8) + 1:]
    EM = maskedDB + H + b'\xbc'
    return EM

# EMSA-PSS Verify function as per RFC 8017
def emsa_pss_verify(M, EM, em_bits, s_len=32, hash_class=hashlib.sha256):
    m_hash = hash_class(M).digest()
    em_len = (em_bits + 7) // 8
    maskedDB = EM[:em_len - hash_class().digest_size - 1]
    H = EM[em_len - hash_class().digest_size - 1:-1]
    dbMask = mgf1(H, em_len - hash_class().digest_size - 1, hash_class)
    DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
    salt = DB[-s_len:]
    M_prime = b'\x00' * 8 + m_hash + salt
    H_prime = hash_class(M_prime).digest()
    return H == H_prime
