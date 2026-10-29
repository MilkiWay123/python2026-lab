"""Совместимость JSON и обработка повреждённого хранилища."""

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from password_manager import PasswordManager
from password_manager.storage import read_vault


def test_read_previous_format(tmp_path: Path) -> None:
    salt = bytes(range(16))
    key = hashlib.pbkdf2_hmac("sha256", b"old-master", salt, 600_000)
    cipher = Fernet(base64.urlsafe_b64encode(key))
    old_data = {
        "salt": salt.hex(),
        "master_hash": hashlib.sha256(key).hexdigest(),
        "entries": {
            "Учёба": {
                "login": "student",
                "password": cipher.encrypt(b"old-password").decode(),
            }
        },
    }
    path = tmp_path / "old.json"
    path.write_text(json.dumps(old_data), encoding="utf-8")
    manager = PasswordManager(path)
    assert manager.unlock("old-master")
    assert manager.get_entry("Учёба") == ("student", "old-password")
    manager.add_entry("mail", "user", "new-password")
    reloaded = PasswordManager(path)
    assert reloaded.unlock("old-master")
    assert reloaded.get_entry("Учёба") == ("student", "old-password")
    assert reloaded.get_entry("mail") == ("user", "new-password")


@pytest.mark.parametrize("content", ["{", "[]", '{"entries": {}}'])
def test_reject_damaged_file(tmp_path: Path, content: str) -> None:
    path = tmp_path / "damaged.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        read_vault(path)
    assert path.read_text(encoding="utf-8") == content
