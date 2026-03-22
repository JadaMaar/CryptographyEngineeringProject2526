import argparse
import socket
import subprocess

from project.server.helpers.opaque import OpaqueHandler, build_banner
from project.server.helpers.tls import TLSConnection

class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        self.tls_connection = None
        self.opaque_handler = None

        self.init_connection()
        print(f"Client is connecting to port {self.port}")

    def init_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            while True:
                conn, addr = s.accept()
                print(f"Connected by {addr}")
                self.tls_connection = TLSConnection(conn)

                with conn:
                    try:
                        self.tls_connection.tls_handshake()
                    except Exception as e:
                        print(f"Handshake failed: {e}")
                        continue

                    # OPAQUE login or register
                    self.opaque_handler = OpaqueHandler(self.tls_connection)
                    while True:
                        print("Wait for command")
                        failed = False
                        data = self.tls_connection.receive_tls_data().decode()
                        print(f"Received data: {data}")
                        if data == "Register":
                            try:
                                self.opaque_handler.register_user()
                            except Exception as e:
                                failed = True
                                break
                        elif data == "Login":
                            try:
                                if self.opaque_handler.login_user():
                                    break
                            except Exception as e:
                                failed = True
                                # break

                    # Error occurred during login/register e.g. client disconnect
                    if failed:
                        continue

                    # basic banner to show the os of the server
                    self.tls_connection.send_tls_data(build_banner().encode())
                    # Remote shell usage
                    while True:
                        try:
                            data = self.tls_connection.receive_tls_data()
                            if not data:
                                print("Client closed connection.")
                                break

                            result = subprocess.run(
                                data.decode().split(),
                                shell=True,
                                capture_output=True,
                                text=True
                            )

                            output = result.stdout
                            if result.stderr:
                                output += "\n[stderr]\n" + result.stderr

                            self.tls_connection.send_tls_data(output.encode())

                        except Exception as e:
                            try:
                                self.tls_connection.send_tls_data(f"[SERVER ERROR]\n{e}".encode())
                            except:
                                pass
                            break



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