# Accept the SDK spelling without hiding an ordinary trusted_router file provider.
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
    from importlib.machinery import ModuleSpec, PathFinder, SourceFileLoader, SourcelessFileLoader
    from importlib.util import find_spec, spec_from_loader
    from types import CodeType, ModuleType

    module = sys.modules[__name__]
    del module.__dict__["_trusted_router_sdk_alias"]

    def is_alias_finder(finder: object) -> bool:
        return getattr(finder, "_trusted_router_alias", False) is True

    def is_shim(spec: ModuleSpec) -> bool:
        # Only standard file loaders reach here. Identity handles symlinks and
        # case variants; the code marker recognizes separately installed copies.
        try:
            if os.path.samefile(spec.origin, __file__):  # type: ignore[arg-type]
                return True
        except (OSError, ValueError):
            pass
        try:
            code = spec.loader.get_code("trusted_router")  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001 -- Inspection is optional; execution owns errors.
            return False
        return isinstance(code, CodeType) and "_trusted_router_sdk_alias" in code.co_names

    def is_file_provider(spec: ModuleSpec) -> bool:
        # Exact types deliberately exclude wrappers, subclasses, and zip loaders.
        # The location checks also exclude namespace and locationless specs.
        return (
            type(spec.loader) in (SourceFileLoader, SourcelessFileLoader)
            and spec.has_location
            and spec.origin is not None
            and os.path.isfile(spec.origin)
        )

    def other_provider() -> ModuleSpec | None:
        # importlib.reload passes the module being reloaded to every finder.
        reloading = getattr(sys.modules.get("importlib"), "_RELOADING", {})
        target = module if reloading.get("trusted_router") is module else None
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
                try:
                    spec: ModuleSpec | None = discover("trusted_router", path, target)
                except Exception:  # noqa: BLE001, S112 -- Foreign discovery is best effort.
                    continue
                if spec is None or not is_file_provider(spec):
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
        # Standard file loaders create no custom module state, so _exec can
        # retain the locked module and dictionary while restoring its metadata.
        if not hasattr(_bootstrap, "_exec"):
            raise ImportError("trusted_router handoff requires importlib._bootstrap._exec")
        try:
            initializing = module.__spec__._initializing  # type: ignore[union-attr]
        except AttributeError:
            # Reload specs normally lack the flag. Only accept that absence for
            # a reload explicitly tracked by importlib; _exec holds its lock.
            reloading = getattr(sys.modules["importlib"], "_RELOADING", {})
            if reloading.get("trusted_router") is not module:
                raise ImportError(
                    "trusted_router handoff requires the import spec's _initializing attribute"
                ) from None
            initializing = False
        if provider.submodule_search_locations is None:
            module.__dict__.pop("__path__", None)
        # Transfer state before publishing the provider spec to other importers.
        provider._initializing = initializing  # type: ignore[attr-defined]
        try:
            _bootstrap._exec(provider, module)
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
