import socket
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


if __name__ == '__main__':
    # Initialize logging
    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

    # Initialize AES decryption
    AES_KEY = bytes.fromhex('1af4ee7d8b1bd497303905c57f90343a')
    IV = bytes.fromhex('7001153d10c0897fa447af39ea74a95a')
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV), backend=default_backend())

    # Create a raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    logging.info("Server listening for ICMP type 47 packets...")

    while True:
        decryptor = cipher.decryptor()
        packet, addr = s.recvfrom(65535)
        icmp_type = packet[20]

        # Check if the ICMP type is 47
        if icmp_type == 47:
            logging.info(f"ICMP type 47 packet received from {addr[0]}")
            icmp_payload = packet[24:]  # Extracting the payload
            try:
                decrypted_message = decryptor.update(icmp_payload) + decryptor.finalize()
                temp_message = decrypted_message.decode().rstrip('\0')
                logging.info(f"Decrypted message: {temp_message}")
            except Exception as e:
                logging.error(f"Error decrypting message: {e}")
