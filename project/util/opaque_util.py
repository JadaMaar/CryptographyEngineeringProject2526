from ecdsa.ellipticcurve import Point, CurveFp

from project.util.crypto_util import *
import hmac
import project.util.Hash2Curve as Hash2Curve
import json


def random_z_q() -> int:
    return int.from_bytes(os.urandom(32)) % Hash2Curve.q

def KDF(rw: bytes) -> bytes:
    return hkdf_extract(salt=None, input_key_material=rw)


def H(content: bytes) -> bytes:
    return hashlib.sha256(content).digest()

def h(string: bytes) -> Point:
    return Hash2Curve.hash_to_curve(string)

def iterate_hash_with_salt(password: str | bytes, salt: bytes, num_of_iterations: int) -> bytes:
    prev = salt + b'\x00\x00\x01'
    output = bytearray(32)
    for i in range(num_of_iterations):
        u = HMAC(password, prev)
        output = byte_xor(output, u)
        prev = u
    return output

def byte_xor(var, key):
    return bytes(a ^ b for a, b in zip(var, key))


def HMAC(key: bytes, content: bytes) -> bytes:
    return hmac.new(key, content, hashlib.sha256).digest()

def AKE_KeyGen() -> tuple[Point, int]:
    private_key = random_z_q()
    public_key = power(Hash2Curve.g, private_key)

    return Point.from_bytes(Hash2Curve.P256.curve, public_key.to_bytes()), private_key

def KServer(b, y, A, X):
    t1 = power(X, b).to_bytes()
    t2 = power(X, y).to_bytes()
    t3 = power(A, y).to_bytes()
    SK = hkdf_extract(None, t1+t2+t3)
    return SK

def KClient(a, x, B, Y):
    t1 = power(B, x).to_bytes()
    t2 = power(Y, x).to_bytes()
    t3 = power(Y, a).to_bytes()
    SK = hkdf_extract(None, t1+t2+t3)
    return SK

def power(base: Point, exponent: int) -> Point:
    return exponent * base

def inverse(x: int) -> int:
    return pow(x, -1, Hash2Curve.n)

def AEAD_encrypt(key: bytes, data: bytes) -> bytes:
    return aes_gcm_encrypt(key, data, b"")

def AEAD_decrypt(key: bytes, iv: bytes, ct: bytes, tag) -> bytes:
    return aes_gcm_decrypt(key, iv, ct, b"", tag)


def dict_to_bytes(d: dict) -> bytes:
    for k, v in d.items():
        if isinstance(v, Point):
            d[k] = point_to_tuple(v)
    return json.dumps(d).encode("utf-8")

def bytes_to_dict(b: bytes) -> dict:
    js = json.loads(b.decode("utf-8"))
    js["lpk_c"] = tuple_to_point(js["lpk_c"])
    js["lpk_s"] = tuple_to_point(js["lpk_s"])
    return js


def point_to_tuple(point: Point) -> tuple:
    curve: CurveFp = point.curve()
    curve_tuple = (curve.p(), curve.a(), curve.b(), curve.cofactor())
    return curve_tuple, point.x(), point.y()

def tuple_to_point(t) -> Point:
    curve = CurveFp(t[0][0], t[0][1], t[0][2], t[0][3])
    return Point(curve, t[1], t[2])

def point_from_bytes(b: bytes) -> Point:
    return Point.from_bytes(Hash2Curve.P256.curve, b)