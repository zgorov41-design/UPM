from upm.core.engine import PackageEngine
from upm.detector import detect_package

class SnapEngine(PackageEngine):
    name = "snap"
    def inspect(self, path):
        return detect_package(path).to_dict()
    def validate(self, path):
        return detect_package(path).to_dict()
