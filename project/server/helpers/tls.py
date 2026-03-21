import json
import secrets
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from project.util.cert_manager import generate_cert
from project.util.crypto_util import aes_gcm_encrypt, KeySchedule3, hmac_sign, KeySchedule2, KeySchedule1, \
    compute_shared_secret, derive_key_from_shared_secret, generate_ecdh_key_pair, aes_gcm_decrypt, hmac_verify


def send_bytes(conn, data):
    # send length (4 bytes) + data
    conn.sendall(len(data).to_bytes(4, "big"))
    conn.sendall(data)


def recv_bytes(conn):
    length_bytes = b""

    while len(length_bytes) < 4:
        chunk = conn.recv(4 - len(length_bytes))

        if not chunk:
            raise ConnectionError("Client disconnected")

        length_bytes += chunk

    length = int.from_bytes(length_bytes, "big")

    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))

        if not chunk:
            raise ConnectionError("Client disconnected during data transfer")

        data += chunk

    return data

class TLSConnection:
    def __init__(self, connection):
        self.connection = connection
        # TLS values
        self.tls_nonce = None
        self.tls_pk = None
        self.tls_sk = None
        self.tls_ad = None

    def tls_handshake(self) -> bool:
        client_nonce = recv_bytes(self.connection)
        client_pk_bytes = recv_bytes(self.connection)
        client_pk = load_der_public_key(client_pk_bytes)
        print(f"Client nonce: {client_nonce}")
        print(f"Client public key: {client_pk}")

        self.tls_nonce = secrets.token_bytes(32)
        self.tls_sk, self.tls_pk = generate_ecdh_key_pair()
        pk_s_bytes = self.tls_pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        send_bytes(self.connection, self.tls_nonce)
        send_bytes(self.connection, pk_s_bytes)

        shared_secret = compute_shared_secret(self.tls_sk, client_pk)
        derived_key = derive_key_from_shared_secret(shared_secret, b"")
        print(f"Shared secret: {shared_secret}")
        print(f"Derived key: {derived_key}")

        server_kc1, server_ks1 = KeySchedule1(derived_key)
        server_kc2, server_ks2 = KeySchedule2(client_nonce, client_pk_bytes, self.tls_nonce, pk_s_bytes, derived_key)
        cert = generate_cert(pk_s_bytes)
        sigma = self.tls_sk.sign(sha256(client_nonce + client_pk_bytes + self.tls_nonce + pk_s_bytes + cert).digest(),
                          ec.ECDSA(hashes.SHA256()))
        mac_s = hmac_sign(server_ks2,
                          sha256(client_nonce + client_pk_bytes + self.tls_nonce + pk_s_bytes + cert + b"ServerMAC").digest())
        self.kc3, self.ks3 = KeySchedule3(client_nonce, client_pk_bytes, self.tls_nonce, pk_s_bytes, derived_key, sigma, cert,
                                             mac_s)
        data = {
            "cert": cert.hex(),
            "sigma": sigma.hex(),
            "mac": mac_s.hex(),
        }
        message = json.dumps(data).encode("utf-8")

        print(data)

        print(f"server_pk: {pk_s_bytes}")
        print(f"cert: {cert}")


        self.tls_ad = f"Alice, Bob, {pk_s_bytes}, {client_pk_bytes}".encode()
        iv, ciphertext, tag = aes_gcm_encrypt(server_ks1, message, self.tls_ad)


        send_bytes(self.connection, iv)
        send_bytes(self.connection, ciphertext)
        send_bytes(self.connection, tag)

        iv = recv_bytes(self.connection)
        ciphertext = recv_bytes(self.connection)
        tag = recv_bytes(self.connection)

        server_decrypted_message = aes_gcm_decrypt(server_kc1, iv, ciphertext, self.tls_ad, tag)
        print(f"Message decrypted by Server: {server_decrypted_message}")
        server_mac_c = bytes.fromhex(server_decrypted_message.decode())

        print(f"mac: {server_mac_c}")

        assert hmac_verify(server_kc2,
                           sha256(client_nonce + client_pk_bytes + self.tls_nonce + pk_s_bytes + cert + b"ClientMAC").digest(),
                           server_mac_c) == True

        print("Server side TLS finished!")
        return True

    def send_tls_data(self, data):
        iv, ciphertext, tag = aes_gcm_encrypt(self.ks3, data, self.tls_ad)
        send_bytes(self.connection, iv)
        send_bytes(self.connection, ciphertext)
        send_bytes(self.connection, tag)

    def receive_tls_data(self):
        iv = recv_bytes(self.connection)
        ciphertext = recv_bytes(self.connection)
        tag = recv_bytes(self.connection)
        return aes_gcm_decrypt(self.kc3, iv, ciphertext, self.tls_ad, tag)