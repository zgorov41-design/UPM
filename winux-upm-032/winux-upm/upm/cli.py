import argparse
import json
from upm.detector import detect_package
from upm.core.registry import available_engines, get_engine

def _engine_for_path(path):
    detected = detect_package(path)
    if detected.format not in available_engines():
        return None, detected
    return get_engine(detected.format), detected

def main(argv=None):
    parser = argparse.ArgumentParser(prog="upm")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("detect", help="detect package format")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("inspect", help="inspect a package using its engine")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("validate", help="validate a package using its engine")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")

    sub.add_parser("engines", help="list available engines")

    args = parser.parse_args(argv)

    if args.command == "engines":
        print("\n".join(available_engines()))
        return 0

    if args.command == "detect":
        result = detect_package(args.path).to_dict()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    engine, detected = _engine_for_path(args.path)
    if engine is None:
        result = detected.to_dict()
        result["details"]["engine"] = None
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1

    if args.command == "inspect":
        result = engine.inspect(args.path)
        # Inspect is informational: it succeeds when the format is recognized,
        # even if validation reports an invalid package.
        code = 0
    else:
        result = engine.validate(args.path)
        code = 1 if result.get("status") == "invalid" else 0

    result.setdefault("details", {})["engine"] = engine.name
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return code

if __name__ == "__main__":
    raise SystemExit(main())
