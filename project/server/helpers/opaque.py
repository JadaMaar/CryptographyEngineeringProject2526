import platform
import socket
import getpass
from datetime import datetime
from project.server.helpers.database import *
from project.util.opaque_util import *


class OpaqueHandler:
    def __init__(self, connection):
        self.server_k_bundle = None
        self.SK_server = None
        self.tls_connection = connection

    def register_user(self):
        print("Wait for Username and Password")
        self.tls_connection.connection.settimeout(5)
        username = self.tls_connection.receive_tls_data().decode("utf-8")
        password = self.tls_connection.receive_tls_data().decode("utf-8")
        self.tls_connection.connection.settimeout(None)

        print("Check for existing User")
        user = get_user(username)
        if user:
            self.tls_connection.send_tls_data(b"Registration failed. Username is already taken")
            return
        print("Start key calculation")
        s = random_z_q()  # each user should have a unique salt
        rw = H(password.encode() + power(h(password.encode()), s).to_bytes())
        rw_key = KDF(rw)
        lpk_c, lsk_c = AKE_KeyGen()
        lpk_s, lsk_s = AKE_KeyGen()
        client_key_info = {"lpk_c": lpk_c, "lsk_c": lsk_c, "lpk_s": lpk_s}

        print(f"lpk_c: {lpk_c}")
        print(f"lsk_c: {lsk_c}")
        print(f"lpk_s: {lpk_s}")
        enc_client_keys = AEAD_encrypt(rw_key, dict_to_bytes(client_key_info))
        print("insert user into database")
        insert_user(username, s, lpk_c, lpk_s, lsk_s, enc_client_keys)
        self.tls_connection.send_tls_data("Registration was successful")

    def login_user(self):
        self.tls_connection.connection.settimeout(5)
        self.oprf_stage()
        self.ake_stage()
        self.key_confirmation()
        return True

    def oprf_stage(self):
        print("OPRF stage")
        username = self.tls_connection.receive_tls_data().decode("utf-8")
        user = get_user(username)

        h_pw_a = point_from_bytes(self.tls_connection.receive_tls_data())
        print(f"h_pw_a: {h_pw_a}")

        s = user.get("salt", 0)
        self.server_k_bundle = user.get("server_k_bundle", {"lsk_s": None, "lpk_c": None, "lpk_s": None})
        client_enc_k_bundle = user.get("client_enc_k_bundle", pickle.dumps(b"dummy"))
        # print(f"client_enc_k_bundle: {client_enc_k_bundle}")
        h_pw_a_s = power(h_pw_a, s)
        self.tls_connection.send_tls_data(h_pw_a_s.to_bytes())
        self.tls_connection.send_tls_data(client_enc_k_bundle)

    def ake_stage(self):
        print("AKE stage")
        epk_c = point_from_bytes(self.tls_connection.receive_tls_data())
        epk_s, esk_s = AKE_KeyGen()
        b = self.server_k_bundle["lsk_s"]
        y = esk_s
        A = self.server_k_bundle["lpk_c"]
        X = epk_c
        self.SK_server = KServer(b, y, A, X)
        print("SK Server: " + self.SK_server.hex())
        self.tls_connection.send_tls_data(epk_s.to_bytes())

    def key_confirmation(self):
        print("Key confirmation")
        client_mac_c = self.tls_connection.receive_tls_data()
        key = hkdf_expand(self.SK_server, b"Key Confirmation", 32 * 2)
        ServerK_c, ServerK_s = key[:32], key[32:]
        server_mac_c = HMAC(ServerK_c, b"Client KC")
        server_mac_s = HMAC(ServerK_s, b"Server KS")

        self.tls_connection.send_tls_data(server_mac_s)
        # reset timeout before the assert in case of an error
        self.tls_connection.connection.settimeout(None)
        assert server_mac_c == client_mac_c



def build_banner():
    hostname = socket.gethostname()
    user = getpass.getuser()
    os_name = platform.system()
    os_release = platform.release()
    os_version = platform.version()
    arch = platform.machine()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    banner = f"""
========================================
 Welcome to {hostname}
----------------------------------------
 User:        {user}
 OS:          {os_name} {os_release}
 Version:     {os_version}
 Architecture:{arch}
 Time:        {now}
========================================
"""
    return banner