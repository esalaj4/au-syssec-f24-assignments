import socket
import sys
# import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

if __name__ == '__main__':
    # Initialize AES encryption
    AES_KEY = bytes.fromhex('1af4ee7d8b1bd497303905c57f90343a')
    IV = bytes.fromhex('7001153d10c0897fa447af39ea74a95a')
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV), backend=default_backend())

    # Validate command line arguments
    if len(sys.argv) != 2:
        print("Usage: python client.py <destination_ip>")
        sys.exit(1)

    destination_ip = sys.argv[1]

    # Create a raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    while True:
        message = input("Enter message: ")
        encryptor = cipher.encryptor()
        if message.lower() == 'exit':
            break

        # Pad message to fit block size and encrypt
        padded_message = message.ljust((len(message) + 15) // 16 * 16, '\0')
        encrypted_message = encryptor.update(padded_message.encode()) + encryptor.finalize()

        # TODO: Proper checksum calculation 
        packet = b'\x2f\x00' + b'\x00\x00' + encrypted_message  # Type 47, Code 0, Checksum 0, followed by data
        #      Type=47(x2f)  Code=0(x00)  Checksum=0  Payload
        s.sendto(packet, (destination_ip, 0))
