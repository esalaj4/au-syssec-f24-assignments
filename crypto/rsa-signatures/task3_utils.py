import hashlib
import secrets

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
        a = secrets.randbelow(n - 3) + 2  # Use secrets.randbelow for secure random number generation
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
    p = secrets.randbits(n)
    p |= (1 << n - 1) | 1
    return p

def generate_prime_number(n):
    p = generate_prime_candidate(n)
    while not is_prime(p, 128):
        p = generate_prime_candidate(n)
    return p

def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha256):
    h_len = hash_class().digest_size
    t = b""
    for counter in range(0, (mask_len // h_len) + 1):
        C = counter.to_bytes(4, 'big')
        t += hash_class(mgf_seed + C).digest()
    return t[:mask_len]
