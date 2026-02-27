from dilithium_py.ml_dsa import ML_DSA_44


auth_pk, auth_sk = ML_DSA_44.keygen()

def generate_cert(key):
    return ML_DSA_44.sign(auth_sk, key)

def verify_cert(cert, key):
    ML_DSA_44.verify(auth_pk, key, cert)