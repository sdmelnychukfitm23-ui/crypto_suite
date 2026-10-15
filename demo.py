"""Автоматична демонстрація ВСІХ вимог завдання. Запуск: python demo.py
Після кожного блоку є мітка [СКРІНШОТ N] - у цей момент можна робити знімок екрана."""
import os
import shutil
import sys
import tempfile

import asym
import hybrid
import sym
from errors import CryptoError
from logger import log_event

PW = "Demo#Pass2025"
BASE = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR = os.path.join(BASE, "outputs", "demo")
STORE = os.path.join(DEMO_DIR, "keystore_demo.json")
SAMPLE = "Привіт! Це секретне повідомлення для практичної роботи №3-4.".encode("utf-8")


def title(t):
    print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)


def expect_error(label, fn):
    try:
        fn()
        print(f"  [!] {label}: помилку НЕ виявлено (це погано)")
    except CryptoError as e:
        print(f"  [OK] {label}\n       -> {type(e).__name__}: {e}")
        log_event("demo-exception", "FAIL", case=label, error=type(e).__name__)


def main():
    shutil.rmtree(DEMO_DIR, ignore_errors=True)
    os.makedirs(DEMO_DIR)

    title("1. СИМЕТРИЧНЕ ШИФРУВАННЯ: ключ, AES-GCM, AES-CBC+HMAC")
    kid = sym.create_key(PW, 256, max_uses=3, store_path=STORE)
    print("Створено ключ:", sym.list_keys(STORE)[0])
    for mode in sym.MODES:
        blob = sym.encrypt(SAMPLE, mode, kid, PW, STORE)
        back = sym.decrypt(blob, PW, STORE)
        print(f"  AES-{mode}: {len(SAMPLE)} Б -> контейнер {len(blob)} Б; розшифровка збігається: {back == SAMPLE}")
    print("Лічильник uses:", sym.list_keys(STORE)[0]["uses"], "/", sym.list_keys(STORE)[0]["max_uses"])
    print("[СКРІНШОТ 1]")

    title("2. РОТАЦІЯ КЛЮЧІВ (політика: ліміт використань)")
    sym.encrypt(SAMPLE, "GCM", kid, PW, STORE)       # 3-є використання
    expect_error("4-те шифрування тим самим ключем (ліміт 3)",
                 lambda: sym.encrypt(SAMPLE, "GCM", kid, PW, STORE))
    new = sym.rotate_key(kid, PW, STORE)
    print(f"  Ротація: старий {kid} -> retired, новий {new}")
    for k in sym.list_keys(STORE):
        print("   ", k["key_id"], k["status"], f"uses={k['uses']}/{k['max_uses']}")
    print("[СКРІНШОТ 2]")

    title("3. АСИМЕТРИЧНЕ: RSA-ключі, PEM, OAEP, підпис PSS")
    priv = asym.generate_rsa(2048)
    asym.save_private(priv, os.path.join(DEMO_DIR, "alice_priv.pem"), PW)
    asym.save_public(priv, os.path.join(DEMO_DIR, "alice_pub.pem"))
    with open(os.path.join(DEMO_DIR, "alice_priv.pem")) as f:
        print(f.read().splitlines()[0], "(приватний ключ зашифровано паролем)")
    with open(os.path.join(DEMO_DIR, "alice_pub.pem")) as f:
        print(f.read())
    priv2 = asym.load_private(os.path.join(DEMO_DIR, "alice_priv.pem"), PW)
    pub2 = asym.load_public(os.path.join(DEMO_DIR, "alice_pub.pem"))
    short = "Короткий текст".encode()
    ct = asym.rsa_encrypt(pub2, short)
    print("  RSA-OAEP: шифртекст", len(ct), "Б; розшифровано:", asym.rsa_decrypt(priv2, ct).decode())
    sig = asym.sign(priv2, SAMPLE)
    print("  Підпис RSA-PSS:", len(sig), "Б; перевірка оригіналу:", asym.verify(pub2, sig, SAMPLE))
    print("  Перевірка ЗМІНЕНОГО повідомлення:", asym.verify(pub2, sig, SAMPLE + b"!"))
    ecc = asym.generate_ec("P-256")
    es = asym.sign(ecc, SAMPLE)
    print("  ECDSA P-256 підпис:", len(es), "Б; перевірка:", asym.verify(ecc.public_key(), es, SAMPLE))
    print("[СКРІНШОТ 3]")

    title("4. ГІБРИДНЕ ШИФРУВАННЯ (RSA-OAEP + AES-256-GCM)")
    big = os.urandom(1_000_000)
    pkg = hybrid.encrypt_hybrid(big, pub2)
    print(f"  Дані 1 000 000 Б -> пакет {len(pkg)} Б (накладні витрати {len(pkg) - len(big)} Б)")
    print("  Розшифровано коректно:", hybrid.decrypt_hybrid(pkg, priv2) == big)
    print("[СКРІНШОТ 4]")

    title("5. ВИНЯТКОВІ СИТУАЦІЇ")
    blob = sym.encrypt(SAMPLE, "GCM", new, PW, STORE)
    bad = bytearray(blob); bad[-1] ^= 1
    expect_error("Пошкоджений тег/шифртекст AES-GCM", lambda: sym.decrypt(bytes(bad), PW, STORE))
    blob2 = sym.encrypt(SAMPLE, "CBC-HMAC", new, PW, STORE)
    bad2 = bytearray(blob2); bad2[-40] ^= 1
    expect_error("Пошкоджений шифртекст CBC (HMAC)", lambda: sym.decrypt(bytes(bad2), PW, STORE))
    expect_error("Неправильний пароль до AES-ключа", lambda: sym.decrypt(blob, "WrongPassword1", STORE))
    expect_error("Невірний формат контейнера", lambda: sym.decrypt("це не контейнер".encode(), PW, STORE))
    expect_error("Неправильний пароль до PEM", lambda: asym.load_private(os.path.join(DEMO_DIR, "alice_priv.pem"), "WrongPassword1"))
    junk = os.path.join(DEMO_DIR, "junk.pem")
    open(junk, "w").write("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
    expect_error("Невірний формат публічного ключа", lambda: asym.load_public(junk))
    bad3 = bytearray(pkg); bad3[-1] ^= 1
    expect_error("Пошкоджений гібридний пакет", lambda: hybrid.decrypt_hybrid(bytes(bad3), priv2))
    other = asym.generate_rsa(2048)
    expect_error("Розшифрування чужим приватним ключем", lambda: hybrid.decrypt_hybrid(pkg, other))
    print("  Підроблений підпис ->", asym.verify(pub2, sig[:-1] + bytes([sig[-1] ^ 1]), SAMPLE))
    print("[СКРІНШОТ 5]")

    title("ГОТОВО. Журнал подій: logs/events.log")
    log_event("demo", "OK")
    with open(os.path.join(BASE, "logs", "events.log"), encoding="utf-8") as f:
        for line in f.readlines()[-6:]:
            print(" ", line.strip())
    print("[СКРІНШОТ 6]")


if __name__ == "__main__":
    main()
