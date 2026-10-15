"""Власні винятки - щоб програма показувала зрозумілі повідомлення, а не 'падала'."""


class CryptoError(Exception):
    """Базовий виняток модуля."""


class InvalidFormatError(CryptoError):
    """Контейнер/ключ має неправильний формат."""


class IntegrityError(CryptoError):
    """Тег автентичності / HMAC / підпис не збігається: дані пошкоджені або підроблені."""


class BadPasswordError(CryptoError):
    """Неправильний пароль до ключа."""


class KeyPolicyError(CryptoError):
    """Ключ вичерпав ліміт використань або прострочений - потрібна ротація."""
