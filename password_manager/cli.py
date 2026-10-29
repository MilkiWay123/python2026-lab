"""Аргументы запуска и команды интерактивного меню."""

import argparse
from getpass import getpass
from pathlib import Path

from cryptography.fernet import InvalidToken

from password_manager import PasswordManager
from password_manager.generator import generate_password


def add_record(manager: PasswordManager) -> None:
    """Запрашивает поля новой записи."""
    name = input("Название: ").strip()
    login = input("Логин: ")
    password = getpass("Пароль: ")
    manager.add_entry(name, login, password)
    print("Запись добавлена.")


def open_storage(manager: PasswordManager, create: bool, unlock: bool) -> None:
    """Создаёт мастер-пароль или проверяет существующий."""
    if manager.initialized:
        if create:
            raise ValueError("Мастер-пароль уже создан. Используйте --unlock.")
        if not manager.unlock(getpass("Мастер-пароль: ")):
            raise ValueError("Неверный мастер-пароль.")
        return
    if unlock:
        raise ValueError("Сначала создайте мастер-пароль через --init.")
    password = getpass("Создайте мастер-пароль: ")
    if password != getpass("Повторите мастер-пароль: "):
        raise ValueError("Пароли не совпадают.")
    manager.init_master(password)


def menu(manager: PasswordManager) -> None:
    """Обрабатывает команды открытого хранилища."""
    print("Команды: add / list / get <name> / delete <name> / exit")
    while True:
        parts = input("> ").strip().split(maxsplit=1)
        if not parts:
            continue
        command = parts[0]
        try:
            if command == "exit":
                return
            if command == "add":
                add_record(manager)
            elif command == "list":
                print("\n".join(manager.list_entries()) or "Записей нет.")
            elif command in {"get", "delete"}:
                if len(parts) != 2:
                    raise ValueError("Укажите название записи после команды.")
                if command == "get":
                    if not manager.unlock(getpass("Подтвердите мастер-пароль: ")):
                        print("Неверный мастер-пароль. Хранилище заблокировано.")
                        return
                    login, password = manager.get_entry(parts[1])
                    print(f"Логин: {login}\nПароль: {password}")
                else:
                    manager.delete_entry(parts[1])
                    print("Запись удалена.")
            else:
                print("Неизвестная команда.")
        except (ValueError, OSError, InvalidToken) as error:
            print(f"Ошибка: {error or 'Не удалось расшифровать запись.'}")


def main() -> None:
    """Разбирает аргументы и выполняет вход."""
    parser = argparse.ArgumentParser(description="Менеджер паролей")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--init", action="store_true", help="создать мастер-пароль")
    actions.add_argument("--unlock", action="store_true", help="открыть хранилище")
    actions.add_argument("--generate", action="store_true", help="сгенерировать пароль")
    parser.add_argument("--file", type=Path, default=Path("passwords.json"))
    args = parser.parse_args()
    try:
        if args.generate:
            print(generate_password())
            return
        manager = PasswordManager(args.file)
        open_storage(manager, args.init, args.unlock)
        menu(manager)
    except (ValueError, OSError, InvalidToken) as error:
        print(f"Ошибка: {error or 'Не удалось расшифровать запись.'}")
    except (EOFError, KeyboardInterrupt):
        print("\nВыход.")
