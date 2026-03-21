import sqlite3

from ecdsa.ellipticcurve import Point

from project.util import Hash2Curve
import pickle


def init_db():
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt BLOB NOT NULL,
            lpk_c BLOB NOT NULL,
            lpk_s BLOB NOT NULL,
            lsk_s BLOB NOT NULL,
            client_enc_k_bundle BLOB NOT NULL
        )
    """)

    conn.commit()
    conn.close()

init_db()

def insert_user(username, s, lpk_c, lpk_s, lsk_s, enc_client_keys):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    print(f"username: {username}")
    print(f"salt: {s.to_bytes(32, "big")}")
    print(f"lpk_c: {lpk_c.to_bytes()}")
    print(f"lpk_s: {lpk_s.to_bytes()}")
    print(f"lsk_s: {lsk_s.to_bytes(32,"big")}")
    enc_client_keys_bytes = pickle.dumps(enc_client_keys)
    print(f"client_enc_k_bundle: {enc_client_keys_bytes}")

    cur.execute("""
        INSERT INTO users 
        (username, salt, lpk_c, lpk_s, lsk_s, client_enc_k_bundle)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        username,
        s.to_bytes(32, "big"),                      # already bytes
        lpk_c.to_bytes(),       # Point → bytes
        lpk_s.to_bytes(),       # Point → bytes
        lsk_s.to_bytes(32,"big"),  # int → 32B
        enc_client_keys_bytes         # should be bytes
    ))

    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect("users.db",  timeout=1)
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    if row:
        print(f"username: {username} found")
        return {
            "user": row[1],
            "salt": int.from_bytes(row[2], "big"),
            "server_k_bundle": {
                "lpk_c": Point.from_bytes(Hash2Curve.P256.curve, row[3]),
                "lpk_s": Point.from_bytes(Hash2Curve.P256.curve, row[4]),
                "lsk_s": int.from_bytes(row[5], "big")
            },
            "client_enc_k_bundle": row[6]
        }

    print(f"username: {username} not found")
    return None