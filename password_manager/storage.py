"""Чтение, проверка и сохранение JSON-хранилища."""

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Entry:
    """Логин и зашифрованный пароль."""

    login: str
    password: str


@dataclass
class Vault:
    """Данные файла без открытого мастер-пароля и ключа."""

    salt: bytes = b""
    master_hash: str = ""
    entries: dict[str, Entry] = field(default_factory=dict)


def read_vault(path: Path) -> Vault:
    """Загружает существующий файл или возвращает пустое хранилище."""
    if not path.exists():
        return Vault()
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Некорректное хранилище.")
    if (
        not isinstance(raw.get("salt"), str)
        or not isinstance(raw.get("master_hash"), str)
        or not isinstance(raw.get("entries"), dict)
    ):
        raise ValueError("Некорректное хранилище.")
    salt = bytes.fromhex(raw["salt"])
    if len(salt) != 16 or len(bytes.fromhex(raw["master_hash"])) != 32:
        raise ValueError("Некорректные параметры мастер-пароля.")
    entries: dict[str, Entry] = {}
    for name, entry in raw["entries"].items():
        if (
            not isinstance(name, str)
            or not isinstance(entry, dict)
            or not isinstance(entry.get("login"), str)
            or not isinstance(entry.get("password"), str)
        ):
            raise ValueError("Некорректная запись в хранилище.")
        entries[name] = Entry(entry["login"], entry["password"])
    return Vault(salt, raw["master_hash"], entries)


def write_vault(path: Path, vault: Vault) -> None:
    """Сохраняет соль, проверочный хэш и записи в прежнем формате JSON."""
    data = {
        "salt": vault.salt.hex(),
        "master_hash": vault.master_hash,
        "entries": {name: asdict(entry) for name, entry in vault.entries.items()},
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
