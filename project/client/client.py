import argparse
import ast
import json
import secrets
import socket
from hashlib import sha256

from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_public_key
from pyexpat.errors import messages

from project.util.crypto_util import generate_ecdh_key_pair, compute_shared_secret, derive_key_from_shared_secret, \
    KeySchedul1, KeySchedul2, aes_gcm_decrypt, hmac_verify, hmac_sign, aes_gcm_encrypt, KeySchedul3


class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.init_connection()

        # TLS values
        self.tls_nonce = None
        self.tls_pk = None
        self.tls_sk = None

        print(f"Client is connecting to port {self.port}")

    def init_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            self.tls_handshake(s)
            #s.sendall(b"Hello, world")
            #data = s.recv(1024)

    def tls_handshake(self, sock) -> bool:
        self.tls_nonce = secrets.token_bytes(32)
        self.tls_sk, self.tls_pk = generate_ecdh_key_pair()
        pk_c_bytes = self.tls_pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        sock.sendall(self.tls_nonce)
        sock.sendall(pk_c_bytes)

        server_nonce = sock.recv(1024)
        server_pk_bytes = sock.recv(1024)
        server_pk = load_der_public_key(server_pk_bytes)
        print(f"Server nonce: {server_nonce}")
        print(f"Server public key: {server_pk}")

        shared_secret = compute_shared_secret(self.tls_sk, server_pk)
        derived_key = derive_key_from_shared_secret(shared_secret, b"")
        print(f"Shared secret: {shared_secret}")
        print(f"Derived key: {derived_key}")

        client_kc1, client_ks1 = KeySchedul1(derived_key)
        client_kc2, client_ks2 = KeySchedul2(self.tls_nonce, pk_c_bytes, server_nonce, server_pk_bytes, derived_key)

        associated_data = b"" #f"Alice, Bob, {server_pk_bytes}, {pk_c_bytes}".encode()
        iv = sock.recv(1024)
        ciphertext = sock.recv(9128)
        tag = sock.recv(1024)

        print(f"iv: {iv}")
        print(f"ciphertext: {ciphertext}")
        print(f"tag: {tag}")

        client_decrypted_message = aes_gcm_decrypt(client_ks1, iv, ciphertext, associated_data, tag)

        js = json.loads(client_decrypted_message.decode("utf-8"))
        print(js)
        cert = bytes.fromhex(js["cert"])
        sigma = bytes.fromhex(js["sigma"])
        mac = bytes.fromhex(js["mac"])


        print(f"cert: {cert}")
        print(f"sigma: {sigma}")
        print(f"mac: {mac}")

        assert hmac_verify(client_ks2,
                           sha256(self.tls_nonce + pk_c_bytes + server_nonce + server_pk_bytes + cert + b"ServerMAC").digest(),
                           mac) == True

        mac_c = hmac_sign(client_kc2,
                          sha256(self.tls_nonce + pk_c_bytes + server_nonce + server_pk_bytes + cert + b"ClientMAC").digest())
        iv, ciphertext, tag = aes_gcm_encrypt(client_kc1, mac_c.hex(), associated_data)

        print(f"mac: {mac_c}")
        print(f"iv: {iv}")
        print(f"ciphertext: {ciphertext}")
        print(f"tag: {tag}")

        sock.sendall(iv)
        sock.sendall(ciphertext)
        sock.sendall(tag)

        self.kc3, self.ks3 = KeySchedul3(self.tls_nonce, pk_c_bytes, server_nonce, server_pk_bytes, derived_key, sigma,
                                             cert, mac)

        print("Client side TLS finished!")
        return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="My client script")
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=12345,
        help="Port number to run the client on"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to run the client on"
    )
    args = parser.parse_args()
    arg_port = args.port
    arg_host = args.host

    client = Client(arg_host, arg_port)