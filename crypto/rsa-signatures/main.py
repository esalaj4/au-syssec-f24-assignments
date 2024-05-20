import json
import math
import hashlib
from flask import Flask, request, make_response, redirect, url_for
from secret_data import rsa_key
import rsa_pss_implementation as rsa_pss
import secrets

app = Flask(__name__)

def ceil_div(a, b):
    return -(-a // b)

def _and_byte(a, b):
    return bytes([a & b])

def encode_emsa_pss(message: bytes, em_bits: int) -> bytes:
    if len(message) > ((2**64)-1):
        raise ValueError('Too long')

    sha_256 = hashlib.sha256()
    sha_256.update(message)
    m_hash = sha_256.digest()
    h_len = len(m_hash)
    s_len = 32
    em_len = ceil_div(em_bits, 8)


    if em_len < (s_len + h_len + 2):
        raise ValueError('Encoding error')

    salt = secrets.token_bytes(s_len)

    M = bytes(b'\x00' * 8) + m_hash + salt

    sha_256 = hashlib.sha256()
    sha_256.update(M)
    H = sha_256.digest()

    PS = bytes(b'\x00' * (em_len - s_len - h_len - 2))

    DB = PS + b'\x01' + salt

    db_mask = rsa_pss.mask_generation_function(H, em_len - h_len - 1)


    db_mask = rsa_pss.xor_bytes(DB, rsa_pss.mask_generation_function(H, em_len - h_len - 1))


    octets, bits = (8 * em_len - em_bits) // 8, (8 * em_len - em_bits) % 8
    db_mask = (b'\x00' * octets) + db_mask[octets:]
    new_byte = rsa_pss._and_byte(db_mask[octets], 255 >> bits)
    db_mask = db_mask[:octets] + new_byte + db_mask[octets + 1:]

    EM = db_mask + H + b'\xbc'

    return EM


def sign_rsassa_pss(message: bytes) -> bytes:
    N = rsa_key['_n']
    d = rsa_key['_d']
    mod_bits = 3072

    EM = encode_emsa_pss(message, (mod_bits - 1))

    m = rsa_pss.bytes_to_int(EM)
    s = rsa_pss.rsa_private_sign((d, N), m)
    S = rsa_pss.int_to_bytes(s, 128 * 3)

    return S

def verify_emsa_pss(message: bytes, em: bytes, em_bits: int) -> bool:
    if len(message) > ((2**64)-1):
        return False

    sha_256 = hashlib.sha256()
    sha_256.update(message)
    m_hash = sha_256.digest()
    h_len = len(m_hash)
    s_len = 32
    em_len = rsa_pss.integer_ceil(em_bits, 8)


    if em_len < (s_len + h_len + 2):
        return False

    if not rsa_pss._byte_eq(em[-1], b'\xbc'):
        return False

    masked_db, h = em[:em_len - h_len - 1], em[em_len - h_len - 1:-1]

    octets, bits = (8 * em_len - em_bits) // 8, (8 * em_len - em_bits) % 8
    zero = masked_db[:octets] + rsa_pss._and_byte(masked_db[octets], ~(255 >> bits))
    for c in zero:
        if not rsa_pss._byte_eq(c, b'\x00'):
            return False

    db_mask = rsa_pss.mask_generation_function(h, em_len - h_len - 1)

    db_mask = rsa_pss.xor_bytes(masked_db, db_mask)

    new_byte = rsa_pss._and_byte(db_mask[octets], 255 >> bits)
    db = (b'\x00' * octets) + new_byte + db_mask[octets + 1:]

    for c in db[:em_len - h_len - s_len - 2]:
        if not rsa_pss._byte_eq(c, b'\x00'):
            return False
    if not rsa_pss._byte_eq(db[em_len - h_len - s_len - 2], b'\x01'):
        return False

    salt = db[-s_len:]

    m_prime = (b'\x00' * 8) + m_hash + salt

    sha_256 = hashlib.sha256()
    sha_256.update(m_prime)
    h_prime = sha_256.digest()

    result = True
    for x, y in zip(h_prime, h):
        result &= (x == y)
    return result

def verify_rsassa_pss(message: bytes, signature: bytes) -> bool:
    n = rsa_key['_n']
    e = rsa_key['_e']
    mod_bits = 3072
    em_bits = mod_bits - 1
    em_len = rsa_pss.integer_ceil(em_bits, 8)

    if len(signature) != 128 * 3:
        return False

    s = rsa_pss.bytes_to_int(signature)
    m = rsa_pss.rsavp1((n, e), s)
    EM = rsa_pss.int_to_bytes(m, em_len)

    verified = verify_emsa_pss(message, EM, em_bits)

    return verified

@app.route('/')
def index():
    return redirect(url_for('grade'))

@app.route('/pk/')
def pk():
    N = int(rsa_key['_n'])
    e = int(rsa_key['_e'])
    return {'N': N, 'e': e}


@app.route('/grade/')
def grade():
    if 'grade' in request.cookies:
        try:
            j = json.loads(request.cookies.get('grade'))
            msg = bytes.fromhex(j['msg'])
            signature = bytes.fromhex(j['signature'])
            if not verify_rsassa_pss(msg, signature):
                return '<p>Attempted cheating detected!</p>'
            return f'<p>{msg.decode()}</p>'
        except Exception as e:
            response = redirect(url_for('grade'))
            response.delete_cookie('grade')
            return response
    else:
        g = secrets.choice(['-3', '00', '02', '4', '7', '10'])
        msg = f'You get only get a {g} in System Security. I am very disappointed by you.'.encode()
        signature = sign_rsassa_pss(msg)
        j = json.dumps({'msg': msg.hex(), 'signature': signature.hex()})
        response = make_response('<p>Here is your grade, and take a cookie!</p>')
        response.set_cookie('grade', j)
        return response

@app.route('/quote/')
def quote():
    try:
        j = json.loads(request.cookies.get('grade'))
        msg = bytes.fromhex(j['msg'])
        signature = bytes.fromhex(j['signature'])
    except Exception as e:
        print(e)
        return '<p>Grading is not yet done, come back next year.</p>'
