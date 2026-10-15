"""Гібридне шифрування: випадковий AES-256 ключ -> AES-GCM шифрує дані,
сам AES-ключ шифрується публічним ключем одержувача (RSA-OAEP).

Формат пакета:
  MAGIC "CSHYB1\\n\\0" (8 байт) | довжина заголовка (4 байти) | заголовок JSON | шифртекст + тег GCM
  Заголовок: {v, alg, rsa_bits, wrapped_key (b64), nonce (b64)}; він входить у AAD GCM.
"""
import base64
import json
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import asym
from errors import IntegrityError, InvalidFormatError

MAGIC = b"CSHYB1\n\0"


def encrypt_hybrid(data: bytes, recipient_pub) -> bytes:
    session_key = AESGCM.generate_key(bit_length=256)      # CSPRNG
    nonce = os.urandom(12)
    header = {
        "v": 1, "alg": "RSA-OAEP-SHA256 + AES-256-GCM",
        "rsa_bits": recipient_pub.key_size,
        "wrapped_key": base64.b64encode(asym.rsa_encrypt(recipient_pub, session_key)).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }
    hdr = json.dumps(header, sort_keys=True).encode()
    aad = MAGIC + struct.pack(">I", len(hdr)) + hdr
    return aad + AESGCM(session_key).encrypt(nonce, data, aad)


def decrypt_hybrid(blob: bytes, recipient_priv) -> bytes:
    if len(blob) < 12 or not blob.startswith(MAGIC):
        raise InvalidFormatError("Невірний формат гібридного пакета")
    (hlen,) = struct.unpack(">I", blob[8:12])
    if hlen > 8192 or 12 + hlen > len(blob):
        raise InvalidFormatError("Пошкоджений заголовок гібридного пакета")
    try:
        header = json.loads(blob[12:12 + hlen])
        wrapped = base64.b64decode(header["wrapped_key"])
        nonce = base64.b64decode(header["nonce"])
    except (ValueError, KeyError):
        raise InvalidFormatError("Заголовок гібридного пакета пошкоджений")
    session_key = asym.rsa_decrypt(recipient_priv, wrapped)
    try:
        return AESGCM(session_key).decrypt(nonce, blob[12 + hlen:], blob[:12 + hlen])
    except InvalidTag:
        raise IntegrityError("Тег GCM не збігається: пакет пошкоджено або підроблено")
