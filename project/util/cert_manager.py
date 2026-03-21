import json
import os
from dilithium_py.ml_dsa import ML_DSA_44

#auth_pk, auth_sk = ML_DSA_44.keygen()
#with open("auth_key.pem", "w") as f:
#    json.dump({"auth_pk": auth_pk.hex(), "auth_sk": auth_sk.hex()}, f)
# deterministic auth keys
#
# Get directory of the current file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(f"{BASE_DIR}/auth_key.pem", "r") as f:
    data = json.loads(f.read())
    print(data)
    auth_pk = bytes.fromhex(data["auth_pk"])
    auth_sk = bytes.fromhex(data["auth_sk"])

def generate_cert(key):
    return ML_DSA_44.sign(auth_sk, key)

def verify_cert(cert, key):
    return ML_DSA_44.verify(auth_pk, cert, key)