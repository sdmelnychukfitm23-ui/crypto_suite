"""Асиметрична криптографія: RSA (OAEP-шифрування, PSS-підпис) та ECC (ECDSA).
Приватні ключі зберігаються у PEM, зашифрованому паролем (PKCS#8)."""
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from errors import BadPasswordError, IntegrityError, InvalidFormatError

RSA_SIZES = (2048, 3072, 4096)
CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1}
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def generate_rsa(bits: int = 2048):
    if bits not in RSA_SIZES:
        raise InvalidFormatError(f"Розмір RSA має бути одним із {RSA_SIZES}")
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def generate_ec(curve: str = "P-256"):
    if curve not in CURVES:
        raise InvalidFormatError(f"Крива має бути однією з {list(CURVES)}")
    return ec.generate_private_key(CURVES[curve]())


def save_private(key, path: str, password: str) -> None:
    if len(password) < 8:
        raise InvalidFormatError("Пароль до приватного ключа - мінімум 8 символів")
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode()))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem)


def save_public(key, path: str) -> None:
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem)


def load_private(path: str, password: str):
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password.encode())
    except FileNotFoundError:
        raise InvalidFormatError(f"Файл ключа не знайдено: {path}")
    except TypeError:
        raise BadPasswordError("Приватний ключ зашифрований, а пароль не вказано")
    except ValueError as e:
        msg = str(e).lower()
        if "password" in msg or "decrypt" in msg:
            raise BadPasswordError("Неправильний пароль до приватного ключа (PEM)")
        raise InvalidFormatError(f"Невірний формат приватного ключа: {e}")


def load_public(path: str):
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        raise InvalidFormatError(f"Файл ключа не знайдено: {path}")
    except ValueError as e:
        raise InvalidFormatError("Невірний формат публічного ключа (файл не є коректним PEM)")


def rsa_encrypt(pub, data: bytes) -> bytes:
    """RSA-OAEP(SHA-256). Макс. розмір даних: bits/8 - 66 байт (для 2048 -> 190)."""
    try:
        return pub.encrypt(data, OAEP)
    except ValueError as e:
        raise InvalidFormatError(f"Дані завеликі для RSA або ключ не RSA: {e}")


def rsa_decrypt(priv, blob: bytes) -> bytes:
    try:
        return priv.decrypt(blob, OAEP)
    except ValueError:
        raise IntegrityError("RSA-OAEP: розшифрування не вдалося (не той ключ або дані пошкоджені)")


def sign(priv, data: bytes) -> bytes:
    if isinstance(priv, rsa.RSAPrivateKey):
        return priv.sign(data, PSS, hashes.SHA256())
    return priv.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(pub, signature: bytes, data: bytes) -> bool:
    """Повертає True/False (False - підпис невірний або дані змінені)."""
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, data, PSS, hashes.SHA256())
        else:
            pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
