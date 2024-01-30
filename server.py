import argparse
import json
import socket
import time
import zlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from hashlib import sha256
import concurrent.futures
from collections import deque


VERIFICATION_LOG = 'verification_failures.log'
CHECKSUM_LOG = 'checksum_failures.log'

def parse_args():
    parser = argparse.ArgumentParser(description='UDP Server for Packet Verification')
    parser.add_argument('--keys', type=str, help='JSON-encoded keys')
    parser.add_argument('--binaries', type=str, help='JSON-encoded binaries')
    parser.add_argument('-d', '--delay', type=int, default=0, help='Delay for writing to log files (in seconds)')
    parser.add_argument('-p', '--port', type=int, default=1337, help='Server port')
    return parser.parse_args()

def load_keys_and_binaries(keys_str, binaries_str):
    keys = json.loads(keys_str)
    binaries = json.loads(binaries_str)
    return keys, binaries


def verify_signature(data, signature, public_key_path):
    packet_id_hex = hex(int.from_bytes(data[0:4], byteorder='big'))
    packet_seq_num = int.from_bytes(data[4:8], byteorder='big')
    with open(public_key_path, "rb") as key_file:
        public_key_data = key_file.read()

    modBytes = public_key_data[3:]
    mod = int.from_bytes(modBytes, byteorder='big')

    expBytes = public_key_data[0:3]
    exp = int.from_bytes(expBytes, byteorder='big')

    pubkey = rsa.RSAPublicNumbers(exp, mod).public_key(default_backend())
    message = data[:-64]
    try: 
        pubkey.verify( \
                signature=signature, \
                data = message, \
                algorithm=hashes.SHA256(), \
                padding=padding.PKCS1v15() \
        )
    except:
        with open(VERIFICATION_LOG, 'a+') as vlog:
            vlog.write(packet_id_hex + "\n")
            vlog.write(str(packet_seq_num) + "\n")
            vlog.write(hex(pow(int.from_bytes(signature, byteorder='big'), exp, mod))[-64:] + "\n") 
            vlog.write(hex(int.from_bytes(sha256(message).digest(), byteorder='big'))[2:] + "\n\n")

def verify_checksum(data, jpeg_path_file, image_checksum):
    packet_id_hex = hex(int.from_bytes(data[0:4], byteorder='big'))
    packet_seq_num = int.from_bytes(data[4:8], byteorder='big')
    checksum_key = data[8:10]
    checksum_data = data[12:-64]
    cyclic_iter = packet_seq_num
    with open(jpeg_path_file, "rb") as file:
        file_data = file.read()
    for i in range(0, len(checksum_data), 4):
        xor_result = bytes([b ^ checksum_key[j % len(checksum_key)] for j, b in enumerate(checksum_data[i:(i + 4)])])
        image_checksum = zlib.crc32(file_data, image_checksum) & 0xFFFFFFFF
        current_checksum = int.from_bytes(xor_result, byteorder='big')
        if image_checksum != current_checksum:
            with open(CHECKSUM_LOG, "a+") as clog:
                clog.write(packet_id_hex + "\n")
                clog.write(str(packet_seq_num) + "\n")
                clog.write(str(cyclic_iter) + "\n")
                clog.write(hex(current_checksum)[2:]+"\n")
                clog.write(hex(image_checksum)[2:] +"\n\n")
        cyclic_iter += 1
    return image_checksum
        
def main():
    args = parse_args()
    keys, binaries = load_keys_and_binaries(args.keys, args.binaries)
    image_checksum = 0

    def process_packet(data):
        nonlocal image_checksum
        packet_id = hex(int.from_bytes(data[0:4], byteorder='big'))
        signature = data[-64:]
        verify_signature(data, signature, keys[packet_id])
        image_checksum = verify_checksum(data, binaries[packet_id], image_checksum)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        packet_data = deque([])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = ('127.0.0.1', args.port)
        sock.bind(server_address)
        try:
            while True:
                packet_data.append(sock.recv(4096))
                executor.submit(process_packet, packet_data.popleft())


        except KeyboardInterrupt:
            print("Server interrupted. Exiting.")
        finally:
            time.sleep(args.delay)
            sock.close()

if __name__ == '__main__':
    main()