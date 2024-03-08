import requests
import sys
import os
import re
from Crypto.Util.Padding import pad

BLOCK_SIZE = 16


def send_token(token, base_url):
    res = requests.get(f"{base_url}/quote/", cookies={"authtoken": token.hex()})
    return res.text

def xor(iv, dec):
    return bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))


def oracle(iv, block, base_url):
    new_ciphertext = iv + block
    res = send_token(new_ciphertext, base_url)
    return "Padding" not in res and "PKCS#7" not in res


def find_zeroing_iv_block(ciphertext_block, base_url):
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_value in range(1, BLOCK_SIZE + 1):
        padding_iv = [(pad_value ^ b) for b in zeroing_iv]

        for candidate_byte in range(256):
            padding_iv[-pad_value] = candidate_byte
            iv = bytes(padding_iv)

            if oracle(iv, ciphertext_block, base_url):
                if pad_value == 1:
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)

                    if not oracle(iv, ciphertext_block, base_url):
                        continue

                break

        zeroing_iv[-pad_value] = candidate_byte ^ pad_value

    return bytes(zeroing_iv)


def attack(initialization_vector, ciphertext, base_url):
    message = initialization_vector + ciphertext
    blocks = [message[i: i + BLOCK_SIZE] for i in range(0, len(message), BLOCK_SIZE)]
    result = b""
    zeroing_iv_blocks = []
    iv = blocks[0]

    for ciphertext_block in blocks[1:]:
        zeroing_iv_block = find_zeroing_iv_block(ciphertext_block, base_url)
        zeroing_iv_blocks.append(zeroing_iv_block)
        plain_text_block = xor(iv, zeroing_iv_block)
        result += plain_text_block
        iv = ciphertext_block

    return result, zeroing_iv_blocks


def encrypt_in_cbc_mode(plaintext, base_url):

    plaintext = plaintext.encode("utf-8")
    plaintext_blocks = [plaintext[i: i + BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)]

    ciphertext_blocks = [bytearray(os.urandom(BLOCK_SIZE))]
    zeroing_iv_blocks = []

    for i in range(len(plaintext_blocks) - 1, 0, -1):
        zeroing_iv_block = find_zeroing_iv_block(bytes(ciphertext_blocks[0]), base_url)
        zeroing_iv_blocks.append(zeroing_iv_block)
        Ci_1 = xor(plaintext_blocks[i], zeroing_iv_block)
        ciphertext_blocks.insert(0, Ci_1)

    zeroing_iv_block = find_zeroing_iv_block(bytes(ciphertext_blocks[0]), base_url)
    zeroing_iv_blocks.append(zeroing_iv_block)
    IV = xor(plaintext_blocks[0], zeroing_iv_block)

    ciphertext = b"".join(ciphertext_blocks)
    return IV, ciphertext


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <base url>", file=sys.stderr)
        exit(1)

    res = requests.get(sys.argv[1])
    requested_token = res.cookies.get_dict().get("authtoken")

    # Extract the initialization vector and ciphertext from the authentication token
    iv, ciphertext = bytes.fromhex(requested_token[:BLOCK_SIZE]), bytes.fromhex(requested_token[BLOCK_SIZE:])

    # Perform the padding oracle attack to recover the plaintext message
    recovered_plaintext, zeroing_iv_blocks = attack(iv, ciphertext, sys.argv[1])

    # Display the recovered secret from the decrypted message
    print(f"Recovered Secret: {recovered_plaintext}")

    # Create a new message to send, indicating that plain CBC is not secure
    text_to_send = recovered_plaintext + " plain CBC is not secure!"
    print(f"Text to Send: {text_to_send}")

    # Pad the text and encrypt it using AES in CBC mode
    padded_text_to_send = pad(text_to_send.encode(), BLOCK_SIZE)
    iv_send, ct_send = encrypt_in_cbc_mode(padded_text_to_send, sys.argv[1])
    bytes_to_send = iv_send + ct_send

    # Send the new token with the modified message to the server
    returned_quote_with_tags = send_token(bytes_to_send, sys.argv[1])

    # Extract and display the stripped content from the server's response
    stripped_content = returned_quote_with_tags.split("\n")[1]
    print(f"Stripped Content: {stripped_content}")
