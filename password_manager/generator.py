"""Генерация паролей с помощью модуля secrets."""

import secrets
import string


def generate_password(length: int = 20) -> str:
    """Выбирает пароль, содержащий символы каждой из четырёх групп."""
    if length < 4:
        raise ValueError("Длина пароля должна быть не меньше 4.")
    groups = (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%&*?")
    alphabet = "".join(groups)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(char in group for char in password) for group in groups):
            return password
