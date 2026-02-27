import argparse
import socket
import subprocess


from project.server.helpers.tls import TLSConnection

class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        self.tls_connection = None

        self.init_connection()
        print(f"Client is connecting to port {self.port}")

    def init_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            while True:  # <-- important
                conn, addr = s.accept()
                print(f"Connected by {addr}")
                self.tls_connection = TLSConnection(conn)

                with conn:
                    try:
                        self.tls_connection.tls_handshake(conn)
                    except Exception as e:
                        print(f"Handshake failed: {e}")
                        continue

                    while True:
                        try:
                            data = self.tls_connection.receive_tls_data(conn)
                            if not data:
                                print("Client closed connection.")
                                break

                            result = subprocess.run(
                                #["powershell", "-Command", data.decode()],
                                data.decode().split(),
                                capture_output=True,
                                text=True
                            )

                            output = result.stdout
                            if result.stderr:
                                output += "\n[stderr]\n" + result.stderr

                            self.tls_connection.send_tls_data(conn, output.encode())

                        except Exception as e:
                            try:
                                self.tls_connection.send_tls_data(conn, f"[SERVER ERROR]\n{e}".encode())
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