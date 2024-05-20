import binascii
import hashlib

def ceil_div(a, b):
    return -(-a // b)

def _and_byte(a, b):
    return bytes([a & b])


def int_to_bytes(integer, length):
    if integer >= 256 ** length:
        raise ValueError('Integer too large for the specified length')
    hex_rep = hex(integer)[2:].rstrip('L')
    if len(hex_rep) % 2 != 0:
        hex_rep = '0' + hex_rep
    byte_rep = binascii.unhexlify(hex_rep)
    return b'\x00' * (length - len(byte_rep)) + byte_rep

def bytes_to_int(byte_seq):
    hex_rep = binascii.hexlify(byte_seq)
    return int(hex_rep, 16)

def rsa_private_sign(private_key: tuple, message: int) -> int:
    d, n = private_key
    if not 0 <= message < n:
        raise ValueError('Message out of range')
    return pow(message, d, n)

def rsa_public_verify(public_key: tuple, signature: int) -> int:
    n, e = public_key
    if not 0 <= signature < n:
        raise ValueError('Signature out of range')
    return pow(signature, e, n)

def xor_bytes(a, b):
    if len(a) != len(b):
        raise ValueError('Byte sequences must be of equal length')
    return bytes(x ^ y for x, y in zip(a, b))

def mask_generation_function(seed, mask_length):
    hash_func = hashlib.sha256
    hash_len = hash_func().digest_size
    if mask_length > 0x10000:
        raise ValueError('Mask length too long')
    output = b''
    for counter in range(ceil_div(mask_length, hash_len)):
        C = int_to_bytes(counter, 4)
        output += hash_func(seed + C).digest()
    return output[:mask_length]

''' Example Usage
if __name__ == "__main__":

    priv_key = (0x12345, 0xABCDE)  # Example private key (d, n)
    pub_key = (0xABCDE, 0x10001)  # Example public key (n, e)

    message = 0x42  # Example message
    signature = rsa_private_sign(priv_key, message)
    print(f'Signature: {signature}')

    verified_message = rsa_public_verify(pub_key, signature)
    print(f'Verified Message: {verified_message}')
'''
