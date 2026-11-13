from __future__ import annotations
from typing import Type
from .engine import PackageEngine

_REGISTRY: dict[str, Type[PackageEngine]] = {}
_BUILTINS_LOADED = False


def register_engine(engine_cls: Type[PackageEngine]) -> Type[PackageEngine]:
    _REGISTRY[engine_cls.format] = engine_cls
    return engine_cls


def _load_builtins() -> None:
    global _BUILTINS_LOADED
    if not _BUILTINS_LOADED:
        from .. import engines  # noqa: F401
        _BUILTINS_LOADED = True


def get_engine(format_name: str) -> PackageEngine:
    _load_builtins()
    try:
        return _REGISTRY[format_name]()
    except KeyError as exc:
        raise KeyError(f"Unknown package engine: {format_name}") from exc


def available_engines() -> list[str]:
    _load_builtins()
    return sorted(_REGISTRY)
