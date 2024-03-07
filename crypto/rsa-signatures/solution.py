import json
import base64
import requests
import sys

class SignResponse:
    pass

class PK:
    pass

# Function to sign a random document
def sign(hexstring) -> SignResponse:
    response = make_get_request(url + "/sign_random_document_for_students/" + hexstring)
    sign_response = SignResponse()
    sign_response.__dict__.update(response)
    return sign_response

# Function to make a GET request to the specified URL and parse the response as JSON
def make_get_request(url):
    session = requests.session()
    response = session.get(url)
    return json.loads(response.text)

# Function to get the public key
def get_public_key() -> PK:
    response = make_get_request(url + "/pk/")
    public_key = PK()
    public_key.__dict__.update(response)
    return public_key

# Function to get a quote for the given message and signature
def get_quote(msg, signature):
    j = json.dumps({'msg': msg, 'signature': signature})
    base64_data = base64.b64encode(j.encode()).decode()
    
    session = requests.session()
    session.cookies.set('grade', base64_data)
    
    r = session.get(url + '/quote')
    return r

def new_signature(desired_txt):
    pk = get_public_key()
    desired_txt_hex = desired_txt.encode('utf-8').hex()
    desired_txt_bytes = bytes.fromhex(desired_txt_hex)
    desired_txt_int = int.from_bytes(desired_txt_bytes, byteorder='big')

    message_1 = 5
    message_1_sign = sign(f'{message_1:02x}')
    signature_1 = int(message_1_sign.signature, 16)

    message_2 = desired_txt_int // 5 % pk.N
    message_2_sign = sign(f'{message_2:02x}')
    signature_2 = int(message_2_sign.signature, 16)
    message_2 = int.from_bytes(bytes.fromhex(message_2_sign.msg), byteorder='big')

    return signature_1 * signature_2 % pk.N

if __name__ == '__main__':

    url = 'https://cbc-rsa.syssec.dk:8001/'

    # Check if a custom URL is provided via command line argument
    if len(sys.argv) == 2:
        url = sys.argv[1]

    desired_txt = 'You got a 12 because you are an excellent student! :)'
    
    modified_signature = new_signature(desired_txt)

    quote = get_quote(desired_txt.encode('utf-8').hex(), f'{modified_signature:02x}')

    print(quote.text)