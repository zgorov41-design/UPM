_ENGINES = {}
_BUILTINS_LOADED = False

def register_engine(engine):
    _ENGINES[engine.name] = engine

def _load_builtins():
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return
    from upm.engines.deb import DebEngine
    from upm.engines.exe import ExeEngine
    from upm.engines.snap import SnapEngine
    register_engine(DebEngine())
    register_engine(ExeEngine())
    register_engine(SnapEngine())
    _BUILTINS_LOADED = True

def get_engine(name):
    _load_builtins()
    if name not in _ENGINES:
        raise KeyError(name)
    return _ENGINES[name]

def available_engines():
    _load_builtins()
    return sorted(_ENGINES)
