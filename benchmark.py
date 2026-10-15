"""Вимірювання продуктивності. Результати: outputs/benchmark_*.csv та outputs/benchmark.md
Запуск: python benchmark.py   (повний)  або  python benchmark.py --quick  (швидкий)"""
import csv
import os
import statistics
import sys
import time

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC

import asym
import hybrid
from logger import log_event

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")


def timeit(fn, repeats):
    """Медіана часу виконання fn у секундах."""
    times = []
    for _ in range(repeats):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return statistics.median(times)


def bench_aes(sizes, repeats):
    rows = []
    for mode in ("GCM", "CBC-HMAC"):
        for bits in (128, 256):
            key, mac_key = os.urandom(bits // 8), os.urandom(32)
            for size in sizes:
                data = os.urandom(size)
                nonce, iv = os.urandom(12), os.urandom(16)
                if mode == "GCM":
                    enc = lambda: AESGCM(key).encrypt(nonce, data, b"hdr")
                    ct = enc()
                    dec = lambda: AESGCM(key).decrypt(nonce, ct, b"hdr")
                    total = len(ct) + 12
                else:
                    def enc():
                        p = padding.PKCS7(128).padder()
                        padded = p.update(data) + p.finalize()
                        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                        c = e.update(padded) + e.finalize()
                        m = HMAC(mac_key, hashes.SHA256())
                        m.update(c)
                        return c + m.finalize()
                    ct = enc()

                    def dec():
                        c, tag = ct[:-32], ct[-32:]
                        m = HMAC(mac_key, hashes.SHA256())
                        m.update(c)
                        m.verify(tag)
                        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                        u = padding.PKCS7(128).unpadder()
                        return u.update(d.update(c) + d.finalize()) + u.finalize()
                    total = len(ct) + 16
                reps = repeats if size <= 1_000_000 else max(3, repeats // 3)
                te, td = timeit(enc, reps), timeit(dec, reps)
                mb = size / 1_000_000
                rows.append({"mode": mode, "key_bits": bits, "data_bytes": size,
                             "enc_ms": round(te * 1000, 3), "dec_ms": round(td * 1000, 3),
                             "enc_MBps": round(mb / te, 1), "dec_MBps": round(mb / td, 1),
                             "output_bytes": total})
    return rows


def bench_asym(repeats, rsa_sizes):
    rows = []
    msg = os.urandom(32)
    for bits in rsa_sizes:
        t = time.perf_counter()
        priv = asym.generate_rsa(bits)
        gen = time.perf_counter() - t
        pub = priv.public_key()
        ct = asym.rsa_encrypt(pub, msg)
        sig = asym.sign(priv, msg)
        rows.append({"algorithm": f"RSA-{bits}", "keygen_ms": round(gen * 1000, 1),
                     "encrypt_ms": round(timeit(lambda: asym.rsa_encrypt(pub, msg), repeats) * 1000, 3),
                     "decrypt_ms": round(timeit(lambda: asym.rsa_decrypt(priv, ct), repeats) * 1000, 3),
                     "sign_ms": round(timeit(lambda: asym.sign(priv, msg), repeats) * 1000, 3),
                     "verify_ms": round(timeit(lambda: asym.verify(pub, sig, msg), repeats) * 1000, 3),
                     "signature_bytes": len(sig)})
    for curve in asym.CURVES:
        t = time.perf_counter()
        priv = asym.generate_ec(curve)
        gen = time.perf_counter() - t
        pub = priv.public_key()
        sig = asym.sign(priv, msg)
        rows.append({"algorithm": f"ECDSA-{curve}", "keygen_ms": round(gen * 1000, 1),
                     "encrypt_ms": "-", "decrypt_ms": "-",
                     "sign_ms": round(timeit(lambda: asym.sign(priv, msg), repeats) * 1000, 3),
                     "verify_ms": round(timeit(lambda: asym.verify(pub, sig, msg), repeats) * 1000, 3),
                     "signature_bytes": len(sig)})
    return rows


def bench_hybrid(sizes, repeats, rsa_sizes):
    rows = []
    for bits in rsa_sizes:
        priv = asym.generate_rsa(bits)
        pub = priv.public_key()
        for size in sizes:
            data = os.urandom(size)
            blob = hybrid.encrypt_hybrid(data, pub)
            reps = repeats if size <= 1_000_000 else 3
            rows.append({"rsa_bits": bits, "data_bytes": size,
                         "enc_ms": round(timeit(lambda: hybrid.encrypt_hybrid(data, pub), reps) * 1000, 3),
                         "dec_ms": round(timeit(lambda: hybrid.decrypt_hybrid(blob, priv), reps) * 1000, 3),
                         "package_bytes": len(blob)})
    return rows


def write_csv(name, rows):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)


def md_table(rows):
    keys = list(rows[0].keys())
    lines = ["| " + " | ".join(keys) + " |", "|" + "---|" * len(keys)]
    lines += ["| " + " | ".join(str(r[k]) for k in keys) + " |" for r in rows]
    return "\n".join(lines)


def main(quick=False):
    sizes = [1_000, 100_000, 1_000_000] if quick else [1_000, 100_000, 1_000_000, 10_000_000]
    repeats = 5 if quick else 15
    rsa_sizes = (2048, 3072) if quick else asym.RSA_SIZES
    print("Вимірюємо AES...")
    aes = bench_aes(sizes, repeats)
    print("Вимірюємо RSA / ECC (генерація RSA-4096 може тривати кілька секунд)...")
    asy = bench_asym(repeats, rsa_sizes)
    print("Вимірюємо гібридну схему...")
    hyb = bench_hybrid(sizes[:3], repeats, rsa_sizes)
    write_csv("benchmark_aes.csv", aes)
    write_csv("benchmark_asym.csv", asy)
    write_csv("benchmark_hybrid.csv", hyb)
    with open(os.path.join(OUT, "benchmark.md"), "w", encoding="utf-8") as f:
        f.write("## AES (GCM vs CBC+HMAC)\n\n" + md_table(aes) +
                "\n\n## RSA та ECDSA\n\n" + md_table(asy) +
                "\n\n## Гібридна схема (RSA-OAEP + AES-256-GCM)\n\n" + md_table(hyb) + "\n")
    log_event("benchmark", "OK", sizes=sizes)
    print("\n== AES ==\n" + md_table(aes))
    print("\n== RSA / ECC ==\n" + md_table(asy))
    print("\n== Гібрид ==\n" + md_table(hyb))
    print(f"\nФайли збережено в {OUT}")


if __name__ == "__main__":
    main(quick="--quick" in sys.argv)
