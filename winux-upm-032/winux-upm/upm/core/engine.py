class EngineOperationNotSupported(RuntimeError):
    pass

class PackageEngine:
    name = "base"

    def inspect(self, path):
        raise NotImplementedError

    def validate(self, path):
        raise NotImplementedError

    def install(self, path):
        raise EngineOperationNotSupported("install is not implemented")

    def remove(self, path):
        raise EngineOperationNotSupported("remove is not implemented")

    def launch(self, path):
        raise EngineOperationNotSupported("launch is not implemented")
