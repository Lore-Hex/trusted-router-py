# Accept the SDK spelling without hiding another regular trusted_router package.
# Keep bootstrap state local: a server must retain its own dictionary on reload.
from typing import TYPE_CHECKING as _TYPE_CHECKING

if _TYPE_CHECKING:
    from trustedrouter import *  # noqa: F403 -- Re-export the canonical typed API.

del _TYPE_CHECKING


def _trusted_router_sdk_alias() -> None:
    import os
    import sys
    from collections.abc import Sequence
    from importlib import _bootstrap, import_module
    from importlib.abc import Loader, MetaPathFinder
    from importlib.machinery import ModuleSpec, PathFinder
    from importlib.util import find_spec, spec_from_loader
    from types import CodeType, ModuleType

    module = sys.modules[__name__]
    del module.__dict__["_trusted_router_sdk_alias"]

    def is_alias_finder(finder: object) -> bool:
        return getattr(finder, "_trusted_router_alias", False) is True

    def is_shim(spec: ModuleSpec) -> bool:
        # Filesystem identity handles symlinks and case variants. Code markers
        # also recognize separate installs, including zip/wheel importers,
        # without executing another shim (or importing the SDK into a server).
        if spec.origin is not None:
            try:
                if os.path.samefile(spec.origin, __file__):
                    return True
            except (OSError, ValueError):
                pass
        get_code = getattr(spec.loader, "get_code", None)
        code = get_code("trusted_router") if get_code is not None else None
        return code is not None and "_trusted_router_sdk_alias" in code.co_names

    def is_namespace(spec: ModuleSpec) -> bool:
        return (
            spec.origin is None
            and spec.submodule_search_locations is not None
            and (spec.loader is None or type(spec.loader).__name__.endswith("NamespaceLoader"))
        )

    def other_provider() -> ModuleSpec | None:
        finders = list(sys.meta_path)
        if PathFinder not in finders:
            finders.append(PathFinder)
        for finder in finders:
            discover = getattr(finder, "find_spec", None)
            if is_alias_finder(finder) or discover is None:
                continue
            # Let PathFinder interpret entries (including '' and zip paths).
            # Search separately so a second shim cannot conceal a later server.
            paths = ([entry] for entry in sys.path if isinstance(entry, str))
            for path in paths if finder is PathFinder else (None,):
                spec: ModuleSpec | None = discover("trusted_router", path)
                if spec is None or is_namespace(spec):
                    continue
                if not is_shim(spec):
                    return spec
        return None

    class AliasLoader(Loader):
        def __init__(self, canonical: ModuleSpec) -> None:
            self.canonical = canonical

        def create_module(self, spec: ModuleSpec) -> None:
            return None

        def exec_module(self, module: ModuleType) -> None:
            sys.modules[module.__name__] = import_module(self.canonical.name)

        def get_code(self, fullname: str) -> CodeType | None:
            get_code = getattr(self.canonical.loader, "get_code", None)
            code: CodeType | None = get_code(self.canonical.name) if get_code is not None else None
            return code

    class AliasFinder(MetaPathFinder):
        _trusted_router_alias = True

        def find_spec(
            self, fullname: str, path: Sequence[str] | None = None,
            target: ModuleType | None = None,
        ) -> ModuleSpec | None:
            if not fullname.startswith("trusted_router."):
                return None
            sdk = sys.modules.get("trustedrouter")
            if sdk is None or sys.modules.get("trusted_router") is not sdk:
                return None
            canonical = find_spec("trustedrouter" + fullname[len("trusted_router"):])
            if canonical is None:
                return None
            return spec_from_loader(fullname, AliasLoader(canonical),
                                    is_package=canonical.submodule_search_locations is not None)

    provider = other_provider()
    if provider is not None:
        sys.meta_path[:] = [finder for finder in sys.meta_path if not is_alias_finder(finder)]
        for name, cached in list(sys.modules.items()):
            if (name.startswith("trusted_router.")
                    and cached is sys.modules.get("trustedrouter" + name[len("trusted_router"):])):
                del sys.modules[name]
        # _exec is importlib's reload primitive: retain the locked module and its
        # dictionary, restore all provider metadata, and support legacy loaders.
        # Transfer initialization state before _exec publishes the provider spec.
        initializing = getattr(module.__spec__, "_initializing", False)
        provider._initializing = initializing  # type: ignore[attr-defined]
        try:
            _bootstrap._exec(provider, module)  # type: ignore[attr-defined]
        except BaseException:
            if initializing:
                sys.modules.pop("trusted_router", None)
            raise
        finally:
            provider._initializing = False  # type: ignore[attr-defined]
    else:
        sdk = import_module("trustedrouter")
        if not any(is_alias_finder(finder) for finder in sys.meta_path):
            sys.meta_path.insert(0, AliasFinder())
        sys.modules[__name__] = sdk


_trusted_router_sdk_alias()
