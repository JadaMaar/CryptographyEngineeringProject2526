import argparse
import json
import socket
import secrets
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec

from project.util.cert_manager import generate_cert
from project.util.crypto_util import generate_ecdh_key_pair, compute_shared_secret, derive_key_from_shared_secret, \
    KeySchedul1, KeySchedul2, hmac_sign, KeySchedul3, aes_gcm_encrypt, aes_gcm_decrypt, hmac_verify


class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        # TLS values
        self.tls_nonce = None
        self.tls_pk = None
        self.tls_sk = None

        self.init_connection()
        print(f"Client is connecting to port {self.port}")

    def init_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                try:
                    self.tls_handshake(conn)
                except Exception as e:
                    print("Error: TLS handshake failed")
                    return

                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    conn.sendall(data)

    def tls_handshake(self, connection) -> bool:
        client_nonce = connection.recv(1024)
        client_pk_bytes = connection.recv(1024)
        client_pk = load_der_public_key(client_pk_bytes)
        print(f"Client nonce: {client_nonce}")
        print(f"Client public key: {client_pk}")

        self.tls_nonce = secrets.token_bytes(32)
        self.tls_sk, self.tls_pk = generate_ecdh_key_pair()
        pk_s_bytes = self.tls_pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        connection.sendall(self.tls_nonce)
        connection.sendall(pk_s_bytes)

        shared_secret = compute_shared_secret(self.tls_sk, client_pk)
        derived_key = derive_key_from_shared_secret(shared_secret, b"")
        print(f"Shared secret: {shared_secret}")
        print(f"Derived key: {derived_key}")

        server_kc1, server_ks1 = KeySchedul1(derived_key)
        server_kc2, server_ks2 = KeySchedul2(client_nonce, client_pk_bytes, self.tls_nonce, pk_s_bytes, derived_key)
        cert = generate_cert(pk_s_bytes)
        sigma = self.tls_sk.sign(sha256(client_nonce + client_pk_bytes + self.tls_nonce + pk_s_bytes + cert).digest(),
                          ec.ECDSA(hashes.SHA256()))
        mac_s = hmac_sign(server_ks2,
                          sha256(client_nonce + client_pk_bytes + self.tls_nonce + pk_s_bytes + cert + b"ServerMAC").digest())
        self.kc3, self.ks3 = KeySchedul3(client_nonce, client_pk_bytes, self.tls_nonce, pk_s_bytes, derived_key, sigma, cert,
                                             mac_s)
        data = {
            "cert": cert.hex(),
            "sigma": sigma.hex(),
            "mac": mac_s.hex(),
        }
        message = json.dumps(data).encode("utf-8")

        print(data)


        associated_data = b"" #f"Alice, Bob, {pk_s_bytes}, {client_pk_bytes}".encode()
        iv, ciphertext, tag = aes_gcm_encrypt(server_ks1, message, associated_data)


        connection.sendall(iv)
        connection.sendall(ciphertext)
        connection.sendall(tag)

        iv = connection.recv(1024)
        ciphertext = connection.recv(4096)
        tag = connection.recv(1024)

        server_decrypted_message = aes_gcm_decrypt(server_kc1, iv, ciphertext, associated_data, tag)
        print(f"Message decrypted by Server: {server_decrypted_message}")
        server_mac_c = bytes.fromhex(server_decrypted_message.decode())

        print(f"mac: {server_mac_c}")

        assert hmac_verify(server_kc2,
                           sha256(client_nonce + client_pk_bytes + self.tls_nonce + pk_s_bytes + cert + b"ClientMAC").digest(),
                           server_mac_c) == True

        print("Server side TLS finished!")
        return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="My server script")
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=12345,
        help="Port number to run the server on"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to run the server on"
    )
    args = parser.parse_args()
    arg_port = args.port
    arg_host = args.host

    client = Server(arg_host, arg_port)