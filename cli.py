"""Консольний застосунок crypto-suite.
Без аргументів - запускається інтерактивне меню:   python cli.py
Також доступні команди:                            python cli.py --help"""
import argparse
import getpass
import os
import sys
import time

import asym
import hybrid
import sym
from errors import CryptoError
from logger import log_event

BASE = os.path.dirname(os.path.abspath(__file__))
KEYS = os.path.join(BASE, "keys")


def get_password(args, prompt="Пароль: "):
    return getattr(args, "password", None) or os.environ.get("CRYPTO_PASSWORD") or getpass.getpass(prompt)


def read_input(args) -> bytes:
    if getattr(args, "text", None) is not None:
        return args.text.encode("utf-8")
    if getattr(args, "infile", None):
        if not os.path.exists(args.infile):
            raise CryptoError(f"Файл не знайдено: {args.infile}")
        with open(args.infile, "rb") as f:
            return f.read()
    raise CryptoError("Вкажіть --text або --infile")


def write_output(data: bytes, outfile, label="Результат"):
    if outfile:
        os.makedirs(os.path.dirname(os.path.abspath(outfile)), exist_ok=True)
        with open(outfile, "wb") as f:
            f.write(data)
        print(f"{label} збережено у файл: {outfile}")
    else:
        try:
            print(f"{label}: {data.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"{label}: {len(data)} байт (бінарні дані, вкажіть --out)")


def info(**kw):
    for k, v in kw.items():
        print(f"  {k:<14}: {v}")


# ------------------------------------------------------------ обробники
def h_keygen(a):
    pw = get_password(a, "Придумайте пароль до ключа (мін. 8 символів): ")
    kid = sym.create_key(pw, a.bits, a.max_uses)
    print(f"Створено AES-ключ. key_id = {kid}")
    log_event("sym-keygen", "OK", key_id=kid, bits=a.bits)


def h_keys(a):
    keys = sym.list_keys()
    if not keys:
        print("Keystore порожній.")
    for k in keys:
        print(f"  {k['key_id']}  AES-{k['bits']}  status={k['status']}  uses={k['uses']}/{k['max_uses']}  expires={k['expires']}")


def h_rotate(a):
    new = sym.rotate_key(a.key_id, get_password(a))
    print(f"Ключ {a.key_id} -> 'retired'. Новий ключ: {new}")
    log_event("rotate", "OK", old=a.key_id, new=new)


def h_sym_enc(a):
    data, pw = read_input(a), get_password(a)
    t = time.perf_counter()
    blob = sym.encrypt(data, a.mode, a.key_id, pw)
    dt = (time.perf_counter() - t) * 1000
    write_output(blob, a.out or "outputs/encrypted.enc", "Контейнер")
    info(algorithm=f"AES-{a.mode}", key_bits=sym._get_meta(sym._load_store(), a.key_id)["bits"],
         input_bytes=len(data), container_bytes=len(blob), time_ms=f"{dt:.2f}")
    log_event("sym-encrypt", "OK", mode=a.mode, key_id=a.key_id, size=len(data), ms=round(dt, 2))


def h_sym_dec(a):
    with open(a.infile, "rb") as f:
        blob = f.read()
    pw = get_password(a)
    t = time.perf_counter()
    data = sym.decrypt(blob, pw)
    dt = (time.perf_counter() - t) * 1000
    write_output(data, a.out, "Розшифровано")
    info(algorithm="AES (з заголовка)", output_bytes=len(data), time_ms=f"{dt:.2f}")
    log_event("sym-decrypt", "OK", size=len(data), ms=round(dt, 2))


def h_rsa_keygen(a):
    pw = get_password(a, "Пароль для захисту приватного ключа: ")
    t = time.perf_counter()
    priv = asym.generate_rsa(a.bits)
    dt = time.perf_counter() - t
    asym.save_private(priv, os.path.join(KEYS, f"{a.name}_priv.pem"), pw)
    asym.save_public(priv, os.path.join(KEYS, f"{a.name}_pub.pem"))
    print(f"Створено keys/{a.name}_priv.pem (зашифрований паролем) та keys/{a.name}_pub.pem")
    info(algorithm="RSA", key_bits=a.bits, time_s=f"{dt:.2f}")
    log_event("rsa-keygen", "OK", name=a.name, bits=a.bits)


def h_ec_keygen(a):
    pw = get_password(a, "Пароль для захисту приватного ключа: ")
    priv = asym.generate_ec(a.curve)
    asym.save_private(priv, os.path.join(KEYS, f"{a.name}_priv.pem"), pw)
    asym.save_public(priv, os.path.join(KEYS, f"{a.name}_pub.pem"))
    print(f"Створено ECC-ключі ({a.curve}) keys/{a.name}_*.pem")
    log_event("ec-keygen", "OK", name=a.name, curve=a.curve)


def h_rsa_enc(a):
    data = read_input(a)
    pub = asym.load_public(a.pubkey)
    t = time.perf_counter()
    ct = asym.rsa_encrypt(pub, data)
    dt = (time.perf_counter() - t) * 1000
    write_output(ct, a.out or "outputs/rsa_encrypted.bin", "RSA-шифртекст")
    info(algorithm="RSA-OAEP-SHA256", key_bits=pub.key_size, time_ms=f"{dt:.2f}")
    log_event("rsa-encrypt", "OK", bits=pub.key_size, size=len(data))


def h_rsa_dec(a):
    with open(a.infile, "rb") as f:
        blob = f.read()
    priv = asym.load_private(a.privkey, get_password(a, "Пароль до приватного ключа: "))
    write_output(asym.rsa_decrypt(priv, blob), a.out, "Розшифровано")
    log_event("rsa-decrypt", "OK", bits=priv.key_size)


def h_sign(a):
    data = read_input(a)
    priv = asym.load_private(a.privkey, get_password(a, "Пароль до приватного ключа: "))
    sig = asym.sign(priv, data)
    write_output(sig, a.out or "outputs/signature.sig", "Підпис")
    log_event("sign", "OK", size=len(data))


def h_verify(a):
    data = read_input(a)
    with open(a.sig, "rb") as f:
        sig = f.read()
    ok = asym.verify(asym.load_public(a.pubkey), sig, data)
    print("ПІДПИС ВІРНИЙ ✔" if ok else "ПІДПИС НЕВІРНИЙ ✘ (дані змінено або інший ключ)")
    log_event("verify", "OK" if ok else "FAIL")


def h_hyb_enc(a):
    data, pub = read_input(a), asym.load_public(a.pubkey)
    t = time.perf_counter()
    pkg = hybrid.encrypt_hybrid(data, pub)
    dt = (time.perf_counter() - t) * 1000
    write_output(pkg, a.out or "outputs/hybrid.pkg", "Гібридний пакет")
    info(algorithm="RSA-OAEP + AES-256-GCM", rsa_bits=pub.key_size, input_bytes=len(data),
         package_bytes=len(pkg), time_ms=f"{dt:.2f}")
    log_event("hybrid-encrypt", "OK", rsa_bits=pub.key_size, size=len(data), ms=round(dt, 2))


def h_hyb_dec(a):
    with open(a.infile, "rb") as f:
        blob = f.read()
    priv = asym.load_private(a.privkey, get_password(a, "Пароль до приватного ключа: "))
    t = time.perf_counter()
    data = hybrid.decrypt_hybrid(blob, priv)
    dt = (time.perf_counter() - t) * 1000
    write_output(data, a.out, "Розшифровано")
    info(algorithm="RSA-OAEP + AES-256-GCM", time_ms=f"{dt:.2f}")
    log_event("hybrid-decrypt", "OK", ms=round(dt, 2))


def h_bench(a):
    import benchmark
    benchmark.main(quick=a.quick)


# ------------------------------------------------------------ парсер
def build_parser():
    p = argparse.ArgumentParser(description="crypto-suite: AES, RSA, гібридне шифрування, підпис")
    sub = p.add_subparsers(dest="cmd")

    def add(cmd, fn, help_, **opts):
        sp = sub.add_parser(cmd, help=help_)
        sp.set_defaults(fn=fn)
        sp.add_argument("--password", help="пароль (небезпечно у терміналі; краще ввести за запитом)")
        for flag, kw in opts.items():
            sp.add_argument("--" + flag.replace("_", "-"), **kw)
        return sp

    io = {"text": {"help": "текст"}, "infile": {"help": "вхідний файл"}, "out": {"help": "вихідний файл"}}
    add("keygen", h_keygen, "створити AES-ключ", bits={"type": int, "default": 256, "choices": [128, 192, 256]},
        max_uses={"type": int, "default": 100})
    add("keys", h_keys, "показати метадані ключів")
    add("rotate", h_rotate, "ротація AES-ключа", key_id={"required": True})
    add("sym-encrypt", h_sym_enc, "AES шифрування", key_id={"required": True},
        mode={"default": "GCM", "choices": list(sym.MODES)}, **io)
    add("sym-decrypt", h_sym_dec, "AES розшифрування", **{k: v for k, v in io.items() if k != "text"})
    add("rsa-keygen", h_rsa_keygen, "створити RSA-ключі", name={"default": "alice"},
        bits={"type": int, "default": 2048, "choices": list(asym.RSA_SIZES)})
    add("ec-keygen", h_ec_keygen, "створити ECC-ключі (для підпису)", name={"default": "ecc"},
        curve={"default": "P-256", "choices": list(asym.CURVES)})
    add("rsa-encrypt", h_rsa_enc, "RSA-OAEP (малі дані)", pubkey={"required": True}, **io)
    add("rsa-decrypt", h_rsa_dec, "RSA-OAEP розшифрування", privkey={"required": True},
        **{k: v for k, v in io.items() if k != "text"})
    add("sign", h_sign, "підписати", privkey={"required": True}, **io)
    add("verify", h_verify, "перевірити підпис", pubkey={"required": True}, sig={"required": True},
        text=io["text"], infile=io["infile"])
    add("encrypt-hybrid", h_hyb_enc, "гібридне шифрування", pubkey={"required": True}, **io)
    add("decrypt-hybrid", h_hyb_dec, "гібридне розшифрування", privkey={"required": True},
        **{k: v for k, v in io.items() if k != "text"})
    add("bench", h_bench, "вимірювання продуктивності", quick={"action": "store_true"})
    return p


def run(args) -> int:
    try:
        args.fn(args)
        return 0
    except CryptoError as e:
        print(f"ПОМИЛКА [{type(e).__name__}]: {e}")
        log_event(args.cmd, "FAIL", error=type(e).__name__, message=str(e))
        return 1


# ------------------------------------------------------------ меню
def ask(prompt, default=None):
    v = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return v or default


def menu():
    ns = lambda **kw: argparse.Namespace(password=None, **kw)

    def src():
        if ask("Вхід: 1 - ввести текст, 2 - файл", "1") == "1":
            return {"text": ask("Текст"), "infile": None}
        return {"text": None, "infile": ask("Шлях до файлу")}

    actions = {
        "1": ("Створити AES-ключ", lambda: ("keygen", h_keygen, ns(bits=int(ask("Розмір (128/192/256)", "256")), max_uses=100))),
        "2": ("Показати ключі (метадані)", lambda: ("keys", h_keys, ns())),
        "3": ("AES шифрування", lambda: ("sym-encrypt", h_sym_enc, ns(key_id=ask("key_id"), mode=ask("Режим GCM/CBC-HMAC", "GCM"), out=ask("Вихідний файл", "outputs/encrypted.enc"), **src()))),
        "4": ("AES розшифрування", lambda: ("sym-decrypt", h_sym_dec, ns(infile=ask("Файл контейнера", "outputs/encrypted.enc"), out=None))),
        "5": ("Створити RSA-ключі", lambda: ("rsa-keygen", h_rsa_keygen, ns(name=ask("Ім'я", "alice"), bits=int(ask("Розмір (2048/3072/4096)", "2048"))))),
        "6": ("Гібридне шифрування", lambda: ("encrypt-hybrid", h_hyb_enc, ns(pubkey=ask("Публічний ключ", "keys/alice_pub.pem"), out=ask("Вихідний файл", "outputs/hybrid.pkg"), **src()))),
        "7": ("Гібридне розшифрування", lambda: ("decrypt-hybrid", h_hyb_dec, ns(privkey=ask("Приватний ключ", "keys/alice_priv.pem"), infile=ask("Пакет", "outputs/hybrid.pkg"), out=None))),
        "8": ("Підписати", lambda: ("sign", h_sign, ns(privkey=ask("Приватний ключ", "keys/alice_priv.pem"), out=ask("Файл підпису", "outputs/signature.sig"), **src()))),
        "9": ("Перевірити підпис", lambda: ("verify", h_verify, ns(pubkey=ask("Публічний ключ", "keys/alice_pub.pem"), sig=ask("Файл підпису", "outputs/signature.sig"), **src()))),
        "10": ("Бенчмарк (швидкий)", lambda: ("bench", h_bench, ns(quick=True))),
    }
    while True:
        print("\n=== crypto-suite ===")
        for k, (title, _) in actions.items():
            print(f" {k:>2}. {title}")
        print("  0. Вихід")
        choice = input("Ваш вибір: ").strip()
        if choice == "0":
            return
        if choice not in actions:
            print("Невірний вибір")
            continue
        try:
            cmd, fn, args = actions[choice][1]()
            args.cmd = cmd
            args.fn = fn
            run(args)
        except (ValueError, EOFError) as e:
            print(f"Невірне введення: {e}")


if __name__ == "__main__":
    parser = build_parser()
    parsed = parser.parse_args()
    if not parsed.cmd:
        menu()
    else:
        sys.exit(run(parsed))
