"""Операции с записями и доступ к хранилищу."""

import secrets
from pathlib import Path

from cryptography.fernet import Fernet

from password_manager.security import create_cipher, derive_key, key_hash, verify_key
from password_manager.storage import Entry, Vault, read_vault, write_vault


class PasswordManager:
    """Управляет хранилищем после проверки мастер-пароля."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._vault = Vault()
        self._cipher: Fernet | None = None
        self._load()

    @property
    def initialized(self) -> bool:
        return bool(self._vault.master_hash)

    def _load(self) -> None:
        self._vault = read_vault(self.path)

    def init_master(self, password: str) -> None:
        if self.initialized:
            raise ValueError("Мастер-пароль уже создан.")
        if not password:
            raise ValueError("Мастер-пароль не может быть пустым.")
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        self._vault = Vault(salt, key_hash(key))
        self._persist()
        self._cipher = create_cipher(key)

    def unlock(self, password: str) -> bool:
        self._cipher = None
        if not self.initialized:
            raise ValueError("Сначала создайте мастер-пароль.")
        key = derive_key(password, self._vault.salt)
        if not verify_key(key, self._vault.master_hash):
            return False
        self._cipher = create_cipher(key)
        return True

    def _unlocked(self) -> Fernet:
        if self._cipher is None:
            raise ValueError("Хранилище заблокировано. Введите мастер-пароль.")
        return self._cipher

    def add_entry(self, name: str, login: str, pwd: str) -> None:
        cipher = self._unlocked()
        if not name.strip() or not pwd:
            raise ValueError("Название и пароль не могут быть пустыми.")
        if name in self._vault.entries:
            raise ValueError("Запись с таким названием уже существует.")
        self._vault.entries[name] = Entry(login, cipher.encrypt(pwd.encode()).decode())
        self._persist()

    def list_entries(self) -> list[str]:
        self._unlocked()
        return sorted(self._vault.entries)

    def get_entry(self, name: str) -> tuple[str, str]:
        cipher = self._unlocked()
        entry = self._find_entry(name)
        return entry.login, cipher.decrypt(entry.password.encode()).decode()

    def delete_entry(self, name: str) -> None:
        self._unlocked()
        self._find_entry(name)
        del self._vault.entries[name]
        self._persist()

    def _find_entry(self, name: str) -> Entry:
        if name not in self._vault.entries:
            raise ValueError("Запись не найдена.")
        return self._vault.entries[name]

    def _persist(self) -> None:
        write_vault(self.path, self._vault)
