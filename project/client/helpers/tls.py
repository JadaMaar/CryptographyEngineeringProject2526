import json
import secrets
from hashlib import sha256

from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_public_key

from project.util.cert_manager import verify_cert
from project.util.crypto_util import aes_gcm_encrypt, KeySchedule3, hmac_sign, KeySchedule2, KeySchedule1, \
    compute_shared_secret, derive_key_from_shared_secret, generate_ecdh_key_pair, aes_gcm_decrypt, hmac_verify

def send_bytes(conn, data):
    # send length (4 bytes) + data
    conn.sendall(len(data).to_bytes(4, "big"))
    conn.sendall(data)


def recv_bytes(conn):
    # read 4-byte length first
    length_bytes = b""
    while len(length_bytes) < 4:
        length_bytes += conn.recv(4 - len(length_bytes))
    length = int.from_bytes(length_bytes, "big")

    # then read exactly `length` bytes
    data = b""
    while len(data) < length:
        data += conn.recv(length - len(data))
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
        self.tls_nonce = secrets.token_bytes(32)
        self.tls_sk, self.tls_pk = generate_ecdh_key_pair()
        pk_c_bytes = self.tls_pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        send_bytes(self.connection, self.tls_nonce)
        send_bytes(self.connection, pk_c_bytes)

        server_nonce = recv_bytes(self.connection)
        server_pk_bytes = recv_bytes(self.connection)
        server_pk = load_der_public_key(server_pk_bytes)
        print(f"Server nonce: {server_nonce}")
        print(f"Server public key: {server_pk}")

        shared_secret = compute_shared_secret(self.tls_sk, server_pk)
        derived_key = derive_key_from_shared_secret(shared_secret, b"")
        print(f"Shared secret: {shared_secret}")
        print(f"Derived key: {derived_key}")

        client_kc1, client_ks1 = KeySchedule1(derived_key)
        client_kc2, client_ks2 = KeySchedule2(self.tls_nonce, pk_c_bytes, server_nonce, server_pk_bytes, derived_key)

        self.tls_ad = f"Alice, Bob, {server_pk_bytes}, {pk_c_bytes}".encode()
        iv = recv_bytes(self.connection)
        ciphertext = recv_bytes(self.connection)
        tag = recv_bytes(self.connection)

        print(f"iv: {iv}")
        print(f"ciphertext: {ciphertext}")
        print(f"tag: {tag}")

        client_decrypted_message = aes_gcm_decrypt(client_ks1, iv, ciphertext, self.tls_ad, tag)

        js = json.loads(client_decrypted_message.decode("utf-8"))
        print(js)
        cert = bytes.fromhex(js["cert"])
        sigma = bytes.fromhex(js["sigma"])
        mac = bytes.fromhex(js["mac"])

        assert verify_cert(server_pk_bytes, cert) == True

        print(f"cert: {cert}")
        print(f"sigma: {sigma}")
        print(f"mac: {mac}")

        assert hmac_verify(client_ks2,
                           sha256(self.tls_nonce + pk_c_bytes + server_nonce + server_pk_bytes + cert + b"ServerMAC").digest(),
                           mac) == True

        mac_c = hmac_sign(client_kc2,
                          sha256(self.tls_nonce + pk_c_bytes + server_nonce + server_pk_bytes + cert + b"ClientMAC").digest())
        iv, ciphertext, tag = aes_gcm_encrypt(client_kc1, mac_c.hex(), self.tls_ad)

        print(f"mac: {mac_c}")
        print(f"iv: {iv}")
        print(f"ciphertext: {ciphertext}")
        print(f"tag: {tag}")

        send_bytes(self.connection, iv)
        send_bytes(self.connection, ciphertext)
        send_bytes(self.connection, tag)

        self.kc3, self.ks3 = KeySchedule3(self.tls_nonce, pk_c_bytes, server_nonce, server_pk_bytes, derived_key, sigma,
                                             cert, mac)

        print("Client side TLS finished!")
        return True

    def send_tls_data(self, data):
        iv, ciphertext, tag = aes_gcm_encrypt(self.kc3, data, self.tls_ad)
        send_bytes(self.connection, iv)
        send_bytes(self.connection, ciphertext)
        send_bytes(self.connection, tag)

    def receive_tls_data(self):
        iv = recv_bytes(self.connection)
        ciphertext = recv_bytes(self.connection)
        tag = recv_bytes(self.connection)
        return aes_gcm_decrypt(self.ks3, iv, ciphertext, self.tls_ad, tag)