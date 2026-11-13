from __future__ import annotations
import argparse
import json
from .detector import detect_package
from .core.registry import available_engines, get_engine
from . import engines  # noqa: F401 - registers built-in engines


def main() -> int:
    parser = argparse.ArgumentParser(prog="upm")
    sub = parser.add_subparsers(dest="command", required=True)

    p_detect = sub.add_parser("detect")
    p_detect.add_argument("path")
    p_detect.add_argument("--json", action="store_true")

    sub.add_parser("engines")

    args = parser.parse_args()
    if args.command == "detect":
        result = detect_package(args.path).to_dict()
        print(json.dumps(result, indent=2, ensure_ascii=False) if args.json else
              f"{result['format']}: {result['status']} - {result['description']}")
        return 0
    if args.command == "engines":
        print("\n".join(available_engines()))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
