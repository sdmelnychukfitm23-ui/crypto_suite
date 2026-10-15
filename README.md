# crypto-suite — симетричне / асиметричне / гібридне шифрування

Навчальний проєкт (ПР №3-4). Python 3 + бібліотека `cryptography`.

## Встановлення
```
pip install -r requirements.txt
```

## Швидкий старт
| Що зробити | Команда |
|---|---|
| Автодемонстрація всіх вимог | `python demo.py` |
| Інтерактивний застосунок (меню) | `python cli.py` |
| Автотести | `python -m unittest discover -s tests -v` |
| Бенчмарки (повні) | `python benchmark.py` |
| Бенчмарки (швидкі) | `python benchmark.py --quick` |

## Команди CLI
```
python cli.py keygen --bits 256                  # новий AES-ключ (виведе key_id)
python cli.py keys                               # метадані ключів
python cli.py rotate --key-id <id>               # ротація
python cli.py sym-encrypt --key-id <id> --mode GCM --text "Привіт" --out outputs/a.enc
python cli.py sym-encrypt --key-id <id> --mode CBC-HMAC --infile data/file.txt --out outputs/b.enc
python cli.py sym-decrypt --infile outputs/a.enc
python cli.py rsa-keygen --name alice --bits 2048
python cli.py rsa-encrypt --pubkey keys/alice_pub.pem --text "коротко" --out outputs/r.bin
python cli.py rsa-decrypt --privkey keys/alice_priv.pem --infile outputs/r.bin
python cli.py sign --privkey keys/alice_priv.pem --infile data/file.txt --out outputs/f.sig
python cli.py verify --pubkey keys/alice_pub.pem --sig outputs/f.sig --infile data/file.txt
python cli.py encrypt-hybrid --pubkey keys/alice_pub.pem --infile data/file.txt --out outputs/h.pkg
python cli.py decrypt-hybrid --privkey keys/alice_priv.pem --infile outputs/h.pkg
```


## Структура
```
cli.py        інтерфейс (меню + команди), інформація про операції
sym.py        AES-GCM, AES-CBC+HMAC, keystore, ротація, формат контейнера
asym.py       RSA-OAEP, RSA-PSS, ECDSA, PEM (приватний ключ під паролем)
hybrid.py     гібридна схема RSA-OAEP + AES-256-GCM
logger.py     JSON-логер з маскуванням секретів
errors.py     власні винятки
benchmark.py  вимірювання продуктивності (CSV + Markdown)
demo.py       автодемонстрація
tests/        unit-тести
```
