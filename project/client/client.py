import argparse
import socket
from project.client.helpers.tls import TLSConnection


class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.init_connection()

        self.tls_connection = None

        print(f"Client is connecting to port {self.port}")

    def init_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            self.tls_connection = TLSConnection(s)
            self.tls_connection.tls_handshake(s)
            #s.sendall(b"Hello, world")
            #data = s.recv(1024)
            while True:
                inp = input("> ")
                self.tls_connection.send_tls_data(s, inp.encode())
                result = self.tls_connection.receive_tls_data(s)
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