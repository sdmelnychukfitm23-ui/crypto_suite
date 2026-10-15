"""Симетричне шифрування: AES-GCM (AEAD) та AES-CBC + HMAC-SHA256 (encrypt-then-MAC).

Ключі:
  * генеруються криптографічно стійким генератором (os.urandom);
  * у keystore.json зберігаються ЛИШЕ метадані + ключ, зашифрований (AES-GCM)
    ключем-обгорткою, що виводиться з пароля через PBKDF2-HMAC-SHA256 + випадковий salt;
  * ведеться лічильник uses та термін дії -> ротація ключів.

Формат контейнера (файл .enc):
  MAGIC (8 байт "CSUITE1\\n") | довжина заголовка (4 байти, big-endian) | заголовок JSON | тіло
  Тіло GCM  = шифртекст + 16-байтний тег
  Тіло CBC  = шифртекст + 32-байтний HMAC
  Заголовок входить до AAD (GCM) / до HMAC (CBC), тому його підміна виявляється.
"""
import base64
import hmac
import json
import os
import struct
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from errors import BadPasswordError, IntegrityError, InvalidFormatError, KeyPolicyError

BASE = os.path.dirname(os.path.abspath(__file__))
KEYSTORE = os.path.join(BASE, "keystore.json")
MAGIC = b"CSUITE1\n"
PBKDF2_ITERATIONS = 600_000
MODES = ("GCM", "CBC-HMAC")
b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s.encode())


# ---------------------------------------------------------------- keystore
def _load_store(path=KEYSTORE) -> dict:
    if not os.path.exists(path):
        return {"keys": {}}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _save_store(store: dict, path=KEYSTORE) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)


def _kek(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def create_key(password: str, bits: int = 256, max_uses: int = 100,
               max_age_days: int = 90, store_path=KEYSTORE) -> str:
    """Генерує новий AES-ключ (128/192/256 біт), шифрує його паролем, пише метадані."""
    if bits not in (128, 192, 256):
        raise InvalidFormatError("Розмір AES-ключа має бути 128, 192 або 256 біт")
    if len(password) < 8:
        raise InvalidFormatError("Пароль занадто короткий (мінімум 8 символів)")
    key = os.urandom(bits // 8)            # CSPRNG операційної системи
    salt = os.urandom(16)                  # випадковий salt для KDF
    nonce = os.urandom(12)
    key_id = uuid.uuid4().hex[:12]
    wrapped = AESGCM(_kek(password, salt, PBKDF2_ITERATIONS)).encrypt(nonce, key, key_id.encode())
    now = datetime.now(timezone.utc)
    store = _load_store(store_path)
    store["keys"][key_id] = {
        "key_id": key_id, "algorithm": "AES", "bits": bits,
        "kdf": "PBKDF2-HMAC-SHA256", "iterations": PBKDF2_ITERATIONS,
        "salt": b64e(salt), "wrap_nonce": b64e(nonce), "wrapped_key": b64e(wrapped),
        "created": now.isoformat(timespec="seconds"),
        "expires": (now + timedelta(days=max_age_days)).isoformat(timespec="seconds"),
        "uses": 0, "max_uses": max_uses, "status": "active",
    }
    _save_store(store, store_path)
    return key_id


def _get_meta(store, key_id):
    if key_id not in store["keys"]:
        raise InvalidFormatError(f"Ключ з id '{key_id}' не знайдено у keystore")
    return store["keys"][key_id]


def _unwrap(meta: dict, password: str) -> bytes:
    try:
        return AESGCM(_kek(password, b64d(meta["salt"]), meta["iterations"])).decrypt(
            b64d(meta["wrap_nonce"]), b64d(meta["wrapped_key"]), meta["key_id"].encode())
    except InvalidTag:
        raise BadPasswordError("Неправильний пароль до ключа")


def _check_policy(meta: dict) -> None:
    if meta["status"] != "active":
        raise KeyPolicyError(f"Ключ {meta['key_id']} має статус '{meta['status']}' - потрібна ротація")
    if meta["uses"] >= meta["max_uses"]:
        raise KeyPolicyError(f"Ключ {meta['key_id']} вичерпав ліміт використань ({meta['max_uses']})")
    if datetime.now(timezone.utc) > datetime.fromisoformat(meta["expires"]):
        raise KeyPolicyError(f"Термін дії ключа {meta['key_id']} минув")


def rotate_key(old_id: str, password: str, store_path=KEYSTORE) -> str:
    """Ротація: старий ключ -> 'retired' (лише розшифрування), створюється новий."""
    store = _load_store(store_path)
    old = _get_meta(store, old_id)
    _unwrap(old, password)                       # перевірка пароля
    new_id = create_key(password, old["bits"], old["max_uses"], 90, store_path)
    store = _load_store(store_path)
    store["keys"][old_id]["status"] = "retired"
    _save_store(store, store_path)
    return new_id


def list_keys(store_path=KEYSTORE) -> list:
    """Повертає лише метадані (без матеріалу ключа)."""
    hide = {"wrapped_key", "wrap_nonce", "salt"}
    return [{k: v for k, v in m.items() if k not in hide}
            for m in _load_store(store_path)["keys"].values()]


# ---------------------------------------------------------------- контейнер
def _pack(header: dict, body_fn):
    hdr = json.dumps(header, sort_keys=True).encode()
    aad = MAGIC + struct.pack(">I", len(hdr)) + hdr
    return aad + body_fn(aad)


def _unpack(blob: bytes):
    if len(blob) < len(MAGIC) + 4 or not blob.startswith(MAGIC):
        raise InvalidFormatError("Невірний формат контейнера (немає сигнатури CSUITE1)")
    (hlen,) = struct.unpack(">I", blob[8:12])
    if hlen > 4096 or 12 + hlen > len(blob):
        raise InvalidFormatError("Пошкоджений заголовок контейнера")
    try:
        header = json.loads(blob[12:12 + hlen])
    except ValueError:
        raise InvalidFormatError("Заголовок контейнера не є коректним JSON")
    return header, blob[:12 + hlen], blob[12 + hlen:]


def _split_keys(master: bytes, bits: int):
    okm = HKDF(algorithm=SHA256(), length=bits // 8 + 32, salt=None,
               info=b"crypto-suite cbc-hmac").derive(master)
    return okm[:bits // 8], okm[bits // 8:]


def encrypt(data: bytes, mode: str, key_id: str, password: str, store_path=KEYSTORE) -> bytes:
    if mode not in MODES:
        raise InvalidFormatError(f"Невідомий режим '{mode}'. Доступні: {MODES}")
    store = _load_store(store_path)
    meta = _get_meta(store, key_id)
    _check_policy(meta)
    master = _unwrap(meta, password)
    header = {"v": 1, "mode": mode, "key_bits": meta["bits"], "key_id": key_id}

    if mode == "GCM":
        nonce = os.urandom(12)                       # 96-бітний випадковий nonce
        header["nonce"] = b64e(nonce)
        blob = _pack(header, lambda aad: AESGCM(master).encrypt(nonce, data, aad))
    else:
        iv = os.urandom(16)
        header["iv"] = b64e(iv)
        enc_key, mac_key = _split_keys(master, meta["bits"])

        def body(aad):
            padder = padding.PKCS7(128).padder()
            padded = padder.update(data) + padder.finalize()
            enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
            ct = enc.update(padded) + enc.finalize()
            mac = HMAC(mac_key, hashes.SHA256())
            mac.update(aad + ct)                      # encrypt-then-MAC
            return ct + mac.finalize()
        blob = _pack(header, body)

    meta["uses"] += 1                                 # лічильник використань
    _save_store(store, store_path)
    return blob


def decrypt(blob: bytes, password: str, store_path=KEYSTORE) -> bytes:
    header, aad, body = _unpack(blob)
    try:
        mode, key_id = header["mode"], header["key_id"]
    except KeyError:
        raise InvalidFormatError("У заголовку бракує обов'язкових полів")
    meta = _get_meta(_load_store(store_path), key_id)
    master = _unwrap(meta, password)

    try:
        if mode == "GCM":
            return AESGCM(master).decrypt(b64d(header["nonce"]), body, aad)
        if mode == "CBC-HMAC":
            if len(body) < 48 or (len(body) - 32) % 16:
                raise InvalidFormatError("Неправильна довжина шифртексту")
            enc_key, mac_key = _split_keys(master, meta["bits"])
            ct, tag = body[:-32], body[-32:]
            mac = HMAC(mac_key, hashes.SHA256())
            mac.update(aad + ct)
            expected = mac.finalize()
            if not hmac.compare_digest(expected, tag):   # СПОЧАТКУ перевірка MAC
                raise IntegrityError("HMAC не збігається: дані пошкоджені або підроблені")
            dec = Cipher(algorithms.AES(enc_key), modes.CBC(b64d(header["iv"]))).decryptor()
            padded = dec.update(ct) + dec.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()
    except InvalidTag:
        raise IntegrityError("Тег автентичності GCM не збігається: дані пошкоджені або підроблені")
    except KeyError:
        raise InvalidFormatError("У заголовку бракує обов'язкових полів")
    raise InvalidFormatError(f"Невідомий режим '{mode}'")
