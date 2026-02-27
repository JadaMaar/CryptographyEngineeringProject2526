from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import secrets
import ast
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)

HASH_FUNC = hashes.SHA256() # Use SHA256
KEY_LEN = 32 # 32 bytes

# Generate ECDH private and public key pair
def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Compute the shared secret using ECDH
def compute_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

# HKDF to derive symmetric key from shared secret
def derive_key_from_shared_secret(shared_secret, salt=None, info=b"handshake data"):
    if salt is None:
        salt = os.urandom(16)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        info=info,
    ).derive(shared_secret)
    return derived_key

def DeriveHS(key):
    zero_bytes = b"\x00" * 32
    ES = hkdf_extract(zero_bytes,zero_bytes)  # 0 = zeros (bytes) of length 32
    dES = hkdf_expand(ES, sha256(b"DerivedES").digest())
    HS = hkdf_extract(dES, sha256(key).digest())
    return HS

# HKDF.Extract
def hkdf_extract(salt, input_key_material, length=KEY_LEN):
    # Extract: Derive the PRK (pseudorandom key)
    hkdf_extract = HKDF(
        algorithm=HASH_FUNC,
        length=length,             # Length of the PRK (match SHA-256 output: 32 bytes)
        salt=salt,             # Salt can be any value or None
        info=None,             # No info for Extract phase
        backend=default_backend()
    )
    prk = hkdf_extract.derive(input_key_material)
    return prk

# HKDF.Expand
def hkdf_expand(prk, info, length=KEY_LEN):
    # Expand: Derive the final key from the PRK
    hkdf_expand = HKDF(
        algorithm=HASH_FUNC,
        length=length,         # Desired output length of the final derived key
        salt=None,             # No salt in the Expand phase (PRK is used directly as key)
        info=info,             # Context-specific info parameter
        backend=default_backend()
    )
    derived_key = hkdf_expand.derive(prk)
    return derived_key

def KeySchedule1(key):
    hs = DeriveHS(key)
    kc1 = hkdf_expand(hs, sha256(b"ClientKE").digest())
    ks1 = hkdf_expand(hs, sha256(b"ServerKE").digest())
    return kc1, ks1

def KeySchedule2(nonce_c, X, nonce_s, Y, key):
    hs = DeriveHS(key)
    ClientKC = sha256(nonce_c + X + nonce_s + Y + b"ClientKC").digest()
    ServerKC = sha256(nonce_c + X + nonce_s + Y + b"ServerKC").digest()
    kc2 = hkdf_expand(hs, ClientKC)
    ks2 = hkdf_expand(hs, ServerKC)
    return kc2, ks2

def KeySchedule3(nonce_c, X, nonce_s, Y, key, sigma, cert, mac_s):
    hs = DeriveHS(key)
    dHS = hkdf_expand(hs, sha256(b"DHS").digest())
    zero_bytes = b"\x00" * 32
    MS = hkdf_extract(dHS, zero_bytes)
    ClientSKH = sha256(nonce_c + X + nonce_s + Y + sigma + cert + mac_s + b"ClientEncK").digest()
    ServerSKH = sha256(nonce_c + X + nonce_s + Y + sigma + cert + mac_s + b"ServerEncK").digest()
    kc3 = hkdf_expand(MS, ClientSKH)
    ks3 = hkdf_expand(MS, ServerSKH)
    return kc3, ks3

# AES-GCM encryption
def aes_gcm_encrypt(key, plaintext, associated_data):
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8')
    elif isinstance(plaintext, bytes):
        plaintext_bytes = plaintext
    else:
        plaintext_bytes = str(plaintext).encode('utf-8')

    iv = os.urandom(12)  # GCM mode standard IV size is 96 bits (12 bytes)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # Add associated data (not encrypted but authenticated)
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag

# AES-GCM decryption
def aes_gcm_decrypt(key, iv, ciphertext, associated_data, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # Add associated data (must match what was provided during encryption)
    decryptor.authenticate_additional_data(associated_data)

    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

# HMAC_Sign
def hmac_sign(key, message): # compute tag = HMAC(key, message)
    # Create an HMAC object using SHA-256
    h = hmac.HMAC(key, HASH_FUNC, backend=default_backend())
    h.update(message)
    tag = h.finalize()
    # Generate the HMAC code (digest)
    return tag

# HMAC_Verify
def hmac_verify(key, message, tag): # Verify tag =? HMAC(key, message)
    # Create a new HMAC object with the same message and key
    h = hmac.HMAC(key, HASH_FUNC, backend=default_backend())
    h.update(message)
    try:
        # Verify by comparing with the provided signature
        h.verify(tag)
        return True
    except Exception:
        return False


def KeySchedul1(key):
    hs = DeriveHS(key)
    kc1 = hkdf_expand(hs, sha256(b"ClientKE").digest())
    ks1 = hkdf_expand(hs, sha256(b"ServerKE").digest())
    return kc1, ks1

def KeySchedul2(nonce_c, X, nonce_s, Y, key):
    hs = DeriveHS(key)
    ClientKC = sha256(nonce_c + X + nonce_s + Y + b"ClientKC").digest()
    ServerKC = sha256(nonce_c + X + nonce_s + Y + b"ServerKC").digest()
    kc2 = hkdf_expand(hs, ClientKC)
    ks2 = hkdf_expand(hs, ServerKC)
    return kc2, ks2

def KeySchedul3(nonce_c, X, nonce_s, Y, key, sigma, cert, mac_s):
    hs = DeriveHS(key)
    dHS = hkdf_expand(hs, sha256(b"DHS").digest())
    zero_bytes = b"\x00" * 32
    MS = hkdf_expand(dHS, zero_bytes)
    ClientSKH = sha256(nonce_c + X + nonce_s + Y + sigma + cert + mac_s + b"ClientEncK").digest()
    ServerSKH = sha256(nonce_c + X + nonce_s + Y + sigma + cert + mac_s + b"ServerEncK").digest()
    kc3 = hkdf_expand(MS, ClientSKH)
    ks3 = hkdf_expand(MS, ServerSKH)
    return kc3, ks3
