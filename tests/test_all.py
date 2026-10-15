import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import asym, hybrid, sym  # noqa: E402
from errors import *  # noqa: E402,F403

PW = "TestPass#123"


class SymTests(unittest.TestCase):
    def setUp(self):
        self.store = os.path.join(tempfile.mkdtemp(), "ks.json")
        self.kid = sym.create_key(PW, 256, max_uses=2, store_path=self.store)

    def test_roundtrip_both_modes(self):
        for mode in sym.MODES:
            kid = sym.create_key(PW, 128, store_path=self.store)
            blob = sym.encrypt(b"hello" * 100, mode, kid, PW, self.store)
            self.assertEqual(sym.decrypt(blob, PW, self.store), b"hello" * 100)

    def test_tamper_detected(self):
        for mode in sym.MODES:
            kid = sym.create_key(PW, 256, store_path=self.store)
            blob = bytearray(sym.encrypt(b"data", mode, kid, PW, self.store))
            blob[-5] ^= 1
            with self.assertRaises(IntegrityError):
                sym.decrypt(bytes(blob), PW, self.store)

    def test_header_tamper_detected(self):
        blob = sym.encrypt(b"data", "GCM", self.kid, PW, self.store)
        with self.assertRaises(CryptoError):
            sym.decrypt(blob.replace(b'"GCM"', b'"GCN"'), PW, self.store)

    def test_wrong_password_and_format(self):
        blob = sym.encrypt(b"data", "GCM", self.kid, PW, self.store)
        with self.assertRaises(BadPasswordError):
            sym.decrypt(blob, "WrongPass#1", self.store)
        with self.assertRaises(InvalidFormatError):
            sym.decrypt(b"garbage", PW, self.store)

    def test_rotation_and_limit(self):
        sym.encrypt(b"a", "GCM", self.kid, PW, self.store)
        sym.encrypt(b"b", "GCM", self.kid, PW, self.store)
        with self.assertRaises(KeyPolicyError):
            sym.encrypt(b"c", "GCM", self.kid, PW, self.store)
        new = sym.rotate_key(self.kid, PW, self.store)
        self.assertEqual(sym.decrypt(sym.encrypt(b"x", "GCM", new, PW, self.store), PW, self.store), b"x")

    def test_nonce_unique(self):
        a = sym.encrypt(b"same", "GCM", self.kid, PW, self.store)
        b = sym.encrypt(b"same", "GCM", self.kid, PW, self.store)
        self.assertNotEqual(a, b)


class AsymTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = asym.generate_rsa(2048)
        cls.dir = tempfile.mkdtemp()

    def test_pem_roundtrip_and_password(self):
        p = os.path.join(self.dir, "k.pem")
        asym.save_private(self.priv, p, PW)
        self.assertEqual(asym.load_private(p, PW).key_size, 2048)
        with self.assertRaises(BadPasswordError):
            asym.load_private(p, "WrongPass#1")

    def test_oaep(self):
        ct = asym.rsa_encrypt(self.priv.public_key(), b"secret")
        self.assertEqual(asym.rsa_decrypt(self.priv, ct), b"secret")
        with self.assertRaises(InvalidFormatError):
            asym.rsa_encrypt(self.priv.public_key(), b"x" * 500)

    def test_sign_verify(self):
        s = asym.sign(self.priv, b"msg")
        self.assertTrue(asym.verify(self.priv.public_key(), s, b"msg"))
        self.assertFalse(asym.verify(self.priv.public_key(), s, b"msg2"))

    def test_ecdsa(self):
        k = asym.generate_ec("P-384")
        self.assertTrue(asym.verify(k.public_key(), asym.sign(k, b"m"), b"m"))

    def test_hybrid(self):
        data = os.urandom(50_000)
        pkg = hybrid.encrypt_hybrid(data, self.priv.public_key())
        self.assertEqual(hybrid.decrypt_hybrid(pkg, self.priv), data)
        bad = bytearray(pkg); bad[-1] ^= 1
        with self.assertRaises(IntegrityError):
            hybrid.decrypt_hybrid(bytes(bad), self.priv)
        with self.assertRaises(InvalidFormatError):
            hybrid.decrypt_hybrid(b"nope", self.priv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
