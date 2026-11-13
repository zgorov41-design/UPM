"""Command-line interface for Winux UPM 0.2."""
from __future__ import annotations

import argparse
import json
import sys

from .detector import detect_package


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="upm",
        description="Winux Universal Package Manager — safe inspection prototype",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command, help_text in (
        ("detect", "Определить формат файла"),
        ("inspect", "Показать подробности файла"),
        ("validate", "Проверить, насколько файл соответствует формату"),
    ):
        command_parser = subparsers.add_parser(command, help=help_text)
        command_parser.add_argument("file", help="Путь к файлу пакета")
        command_parser.add_argument("--json", action="store_true", help="Вывести результат в JSON")

    return parser


def _print_result(result, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return

    print(f"Файл:        {result.path}")
    print(f"Формат:      {result.format}")
    print(f"Уверенность: {result.confidence}")
    print(f"Статус:      {result.status}")
    print(f"Описание:    {result.description}")
    if result.details:
        print("Подробности:")
        for key, value in result.details.items():
            print(f"  {key}: {value}")


def main() -> int:
    args = build_parser().parse_args()

    try:
        result = detect_package(args.file)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"UPM: ошибка: {exc}", file=sys.stderr)
        return 2

    _print_result(result, args.json)

    if args.command == "validate":
        return 0 if result.status == "valid" else 1
    return 0 if result.format != "UNKNOWN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
