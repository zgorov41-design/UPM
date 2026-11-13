from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any


class EngineOperationNotSupported(RuntimeError):
    """Raised when an engine does not implement a mutating operation yet."""


class PackageEngine(ABC):
    format: str = "unknown"

    @abstractmethod
    def inspect(self, path: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def validate(self, path: str) -> dict[str, Any]:
        raise NotImplementedError

    def install(self, path: str) -> dict[str, Any]:
        raise EngineOperationNotSupported(f"install is not implemented for {self.format}")

    def remove(self, package: str) -> dict[str, Any]:
        raise EngineOperationNotSupported(f"remove is not implemented for {self.format}")

    def launch(self, target: str) -> dict[str, Any]:
        raise EngineOperationNotSupported(f"launch is not implemented for {self.format}")
