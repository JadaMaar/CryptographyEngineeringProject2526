import argparse
import socket
from project.client.helpers.tls import TLSConnection
from project.client.helpers.opaque import OpaqueHandler


class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        self.tls_connection = None
        self.logged_in = False
        self.opaque = None

        self.init_connection()

    def init_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            self.tls_connection = TLSConnection(s)
            self.tls_connection.tls_handshake()
            self.opaque = OpaqueHandler(self.tls_connection)

            print("Welcome, please select one of the following options:\n 1) Register\n 2) Login\n 3) Exit")

            while True:
                inp = input("> ").lower()
                if inp == "register":
                    self.opaque.register_user()
                elif inp == "login":
                    if self.opaque.login_user():
                        break
                elif inp == "exit":
                    return

            # basic banner to show the os of the server
            banner = self.tls_connection.receive_tls_data().decode()
            print(banner)
            # Remote shell connection
            while True:
                inp = input("> ")
                self.tls_connection.send_tls_data(inp.encode())
                result = self.tls_connection.receive_tls_data()
                print(result.decode())


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