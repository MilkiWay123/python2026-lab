"""Получение ключа шифрования и проверка мастер-пароля."""

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet


def derive_key(password: str, salt: bytes) -> bytes:
    """Получает ключ из пароля с помощью PBKDF2."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def key_hash(key: bytes) -> str:
    """Возвращает проверочный хэш ключа для хранения в файле."""
    return hashlib.sha256(key).hexdigest()


def verify_key(key: bytes, expected_hash: str) -> bool:
    """Сравнивает проверочные хэши за постоянное время."""
    return hmac.compare_digest(key_hash(key), expected_hash)


def create_cipher(key: bytes) -> Fernet:
    """Преобразует ключ в формат Fernet."""
    return Fernet(base64.urlsafe_b64encode(key))
