import pickle

from project.util.opaque_util import *


class OpaqueHandler:
    def __init__(self, connection):
        self.tls_connection = connection
        self.client_key_info = None
        self.SK_client = None

    def register_user(self):
        username = input("> Username: ")
        password = input("> Password: ")
        print("Send Register, Username, Password")
        self.tls_connection.send_tls_data("Register")
        self.tls_connection.send_tls_data(username)
        self.tls_connection.send_tls_data(password)
        print("Wait for response")
        response = self.tls_connection.receive_tls_data()
        print(response)

    def login_user(self):
        pass_correct = self.oprf_stage()
        if not pass_correct: return False
        self.ake_stage()
        key_correct = self.key_confirmation()
        if not key_correct: return False
        return True

    def oprf_stage(self):
        username = input("> Username: ")
        password = input("> Password: ")
        h_pw = h(password.encode())
        a = random_z_q()
        h_pw_a = power(h_pw, a)
        self.tls_connection.send_tls_data("Login")
        self.tls_connection.send_tls_data(username)
        self.tls_connection.send_tls_data(h_pw_a.to_bytes())

        h_pw_a_s = Point.from_bytes(Hash2Curve.P256.curve, self.tls_connection.receive_tls_data())
        # turns bytes to tuple of bytes again
        client_enc_k_bundle = pickle.loads(self.tls_connection.receive_tls_data())

        a_inv = inverse(a)
        hp_pw_s = power(h_pw_a_s, a_inv)
        rw = H(password.encode() + hp_pw_s.to_bytes())
        rw_key = KDF(rw)

        print(f"client_enc_bundle: {client_enc_k_bundle}")

        try:
            self.client_key_info = AEAD_decrypt(rw_key, *client_enc_k_bundle)
            self.client_key_info = bytes_to_dict(self.client_key_info)
        except:
            print("Invalid Tag. Password was incorrect!")
            return False
        return True

    def ake_stage(self):
        epk_c, esk_c = AKE_KeyGen()
        self.tls_connection.send_tls_data(epk_c.to_bytes())

        epk_s = point_from_bytes(self.tls_connection.receive_tls_data())
        a = self.client_key_info["lsk_c"]
        x = esk_c
        B = self.client_key_info["lpk_s"]
        Y = epk_s
        self.SK_client = KClient(a, x, B, Y)
        print("SK Client: " + self.SK_client.hex())

    def key_confirmation(self):
        key = hkdf_expand(self.SK_client, b"Key Confirmation", 32 * 2)
        ClientK_c, ClientK_s = key[:32], key[32:]
        client_mac_c = HMAC(ClientK_c, b"Client KC")
        client_mac_s = HMAC(ClientK_s, b"Server KS")

        self.tls_connection.send_tls_data(client_mac_c)
        server_mac_s = self.tls_connection.receive_tls_data()

        if client_mac_s == server_mac_s:
            return True
        else:
            print("Server MAC was incorrect!")
            return False