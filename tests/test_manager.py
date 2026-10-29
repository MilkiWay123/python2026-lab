"""Проверки основных операций менеджера паролей."""

import json
from pathlib import Path

import pytest

from password_manager import PasswordManager
from password_manager.generator import generate_password


@pytest.fixture
def manager(tmp_path: Path) -> PasswordManager:
    result = PasswordManager(tmp_path / "passwords.json")
    result.init_master("master-secret")
    return result


def test_unlock(manager: PasswordManager) -> None:
    assert manager.unlock("master-secret")
    assert not manager.unlock("wrong")
    with pytest.raises(ValueError, match="заблокировано"):
        manager.list_entries()


def test_init_cannot_overwrite(manager: PasswordManager) -> None:
    original = manager.path.read_bytes()
    with pytest.raises(ValueError, match="уже создан"):
        manager.init_master("replacement")
    assert manager.path.read_bytes() == original


def test_add_and_reload(manager: PasswordManager) -> None:
    manager.add_entry("mail", "user", "entry-secret")
    loaded = PasswordManager(manager.path)
    assert loaded.unlock("master-secret")
    assert loaded.list_entries() == ["mail"]
    assert loaded.get_entry("mail") == ("user", "entry-secret")


def test_delete(manager: PasswordManager) -> None:
    manager.add_entry("mail", "user", "entry-secret")
    manager.delete_entry("mail")
    loaded = PasswordManager(manager.path)
    assert loaded.unlock("master-secret")
    assert loaded.list_entries() == []
    with pytest.raises(ValueError, match="не найдена"):
        loaded.get_entry("mail")


def test_encryption_and_salt(manager: PasswordManager, tmp_path: Path) -> None:
    manager.add_entry("mail", "user", "entry-secret")
    content = manager.path.read_text(encoding="utf-8")
    assert "master-secret" not in content
    assert "entry-secret" not in content
    other = PasswordManager(tmp_path / "other.json")
    other.init_master("master-secret")
    first = json.loads(content)
    second = json.loads(other.path.read_text(encoding="utf-8"))
    assert first["salt"] != second["salt"]
    assert first["master_hash"] != second["master_hash"]


def test_generate_password() -> None:
    password = generate_password()
    assert len(password) == 20
    assert any(char.islower() for char in password)
    assert any(char.isupper() for char in password)
    assert any(char.isdigit() for char in password)
    assert any(char in "!@#$%&*?" for char in password)
    with pytest.raises(ValueError):
        generate_password(3)
