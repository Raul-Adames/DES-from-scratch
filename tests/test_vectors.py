from des import DES
from Crypto.Cipher import DES as PyDES
from Crypto.Util.Padding import pad

def test_normal_string():
    des = DES()

    plaintext = "Hello my name is Pepe"
    key = "0f1571c947d9e859"

    test = des.desencriptar(des.encriptar(plaintext, key, 16, 16, 0), key, 16, 16)

    assert test == plaintext


def test_empty_string():
    des = DES()

    plaintext = ""
    key = "A3F1C9D47B2E8056"

    test = des.desencriptar(des.encriptar(plaintext, key, 16, 16, 0), key, 16, 16)

    assert test == plaintext


def test_8bytes_text():
    des = DES()

    plaintext = "ABCDEFGH"
    key = "A3F1C9D47B2E8056"

    test = des.desencriptar(des.encriptar(plaintext, key, 16, 16, 0), key, 16, 16)

    assert test == plaintext


def test_text_encrypt_matches_pycryptodome_ecb_pkcs7():
    des = DES()
    key = "A3F1C9D47B2E8056"
    plaintext = "This is the real test ?"

    my_hex = des.encriptar(plaintext, key, 16, 16, 0)

    key_bytes = bytes.fromhex(key)
    pt = plaintext.encode("utf-8")
    pt_padded = pad(pt, 8)   # DES block size = 8

    ref = PyDES.new(key_bytes, PyDES.MODE_ECB).encrypt(pt_padded).hex()

    assert my_hex.lower() == ref.lower()