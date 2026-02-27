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
            conn, addr = s.accept()
            with conn:
                self.tls_connection = TLSConnection(conn)
                try:
                    self.tls_connection.tls_handshake(conn)
                except Exception as e:
                    print("Error: TLS handshake failed")
                    return

                print(f"Connected by {addr}")
                while True:
                    try:
                        # Receive the command from the client
                        data = self.tls_connection.receive_tls_data(conn)
                        command = data.decode()
                        print(f"Command received: {command}")

                        # Run the command safely
                        result = subprocess.run(command.split(), capture_output=True, text=True, shell=True)

                        # Prepare output
                        output = result.stdout
                        if result.stderr:
                            output += "\n[stderr]\n" + result.stderr

                    except Exception as e:
                        # Capture any error (including invalid command)
                        output = f"[Error executing command]: {str(e)}"

                        # Send output back to client (TLS-encrypted)
                    self.tls_connection.send_tls_data(conn, output.encode())



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