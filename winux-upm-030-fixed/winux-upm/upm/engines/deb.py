from ..detector import detect_package
from ..core.engine import PackageEngine
from ..core.registry import register_engine

@register_engine
class DebEngine(PackageEngine):
    format = "deb"

    def inspect(self, path: str) -> dict:
        return detect_package(path).to_dict()

    def validate(self, path: str) -> dict:
        return detect_package(path).to_dict()
