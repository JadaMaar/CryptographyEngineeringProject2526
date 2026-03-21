import subprocess
import threading
import sys
import time

# Adjust these as needed
SERVER_MODULE = "project.server.server"
CLIENT_MODULE = "project.client.client"
PORT = 9000

print_lock = threading.Lock()  # avoid overlapping prints from threads


def print_prefixed(prefix, *args, **kwargs):
    """Thread-safe printing with a prefix"""
    with print_lock:
        print(f"[{prefix}] ", *args, **kwargs)


def demo():
    # -------------------
    # Helper to read and print output live
    # -------------------
    def reader(stream, prefix):
        for line in iter(stream.readline, ''):
            if line == '':
                break
            print_prefixed(prefix, line, end='')  # line already has newline
        stream.close()

    # -------------------
    # Start the server in background
    # -------------------
    server_proc = subprocess.Popen(
        [sys.executable, "-m", SERVER_MODULE, "-p", str(PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    threading.Thread(target=reader, args=(server_proc.stdout, "SERVER"), daemon=True).start()

    # Give server a moment to start
    time.sleep(1)

    # -------------------
    # Start the client
    # -------------------
    client_proc = subprocess.Popen(
        [sys.executable, "-u", "-m", CLIENT_MODULE, "-p", str(PORT)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    threading.Thread(target=reader, args=(client_proc.stdout, "CLIENT"), daemon=True).start()

    # -------------------
    # Helper to send commands safely
    # -------------------
    def send(cmd):
        client_proc.stdin.write(cmd + "\n")
        client_proc.stdin.flush()
        time.sleep(0.2)  # small delay so output threads can keep up

    # -------------------
    # Demo sequence
    # -------------------
    send("register")
    send("test")  # username
    send("test")  # password

    send("login")
    send("test")  # username
    send("test")  # password

    send("dir")  # run a shell command

    send("exit")  # close client

    # -------------------
    # Clean up
    # -------------------
    client_proc.stdin.close()
    client_proc.wait()

    server_proc.terminate()
    server_proc.wait()

    print_prefixed("INFO", "Server and client terminated.")


if __name__ == "__main__":
    try:
        demo()
    except Exception as e:
        print_prefixed("ERROR", e)