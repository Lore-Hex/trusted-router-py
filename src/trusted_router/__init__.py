"""Accept the SDK's underscored spelling without hiding another package.

An unrelated server owns ``trusted_router`` and can appear after site-packages
via an editable install. Search other providers first and execute the winner
under its real name. A namespace directory (no ``__init__``) is not a provider.
Otherwise share ``trustedrouter`` and its submodules by
identity; the finder redirects imports without executing SDK source twice.
"""
from __future__ import annotations

import sys
from collections.abc import Sequence
from importlib import import_module
from importlib.abc import InspectLoader, Loader, MetaPathFinder
from importlib.machinery import ModuleSpec, PathFinder
from importlib.util import find_spec, module_from_spec, spec_from_loader
from pathlib import Path
from types import CodeType, ModuleType

_FILE = Path(__file__).resolve()
_DIRECTORY = _FILE.parent


def _is_alias_finder(finder: object) -> bool:
    # A marker survives re-imports, which create a new finder class object.
    return getattr(finder, "_trusted_router_alias", False) is True


def _is_namespace(spec: ModuleSpec) -> bool:
    # A bare directory with no ``__init__`` never beats a regular package in
    # ordinary imports, so a stray folder of that name must not hide the SDK.
    return (
        spec.origin is None
        and spec.submodule_search_locations is not None
        and (spec.loader is None or type(spec.loader).__name__.endswith("NamespaceLoader"))
    )


def _other_provider() -> ModuleSpec | None:
    search_path = [entry for entry in sys.path if Path(entry).resolve() != _DIRECTORY.parent]
    finders = list(sys.meta_path)
    if PathFinder not in finders:
        finders.append(PathFinder)
    for finder in finders:
        if _is_alias_finder(finder):
            continue
        spec = finder.find_spec("trusted_router", search_path if finder is PathFinder else None)
        if spec is None or _is_namespace(spec):
            continue
        if spec.origin is not None and Path(spec.origin).resolve() == _FILE:
            continue
        if any(Path(location).resolve() == _DIRECTORY
               for location in spec.submodule_search_locations or ()):
            continue
        return spec
    return None


class _AliasLoader(Loader):
    def __init__(self, canonical: ModuleSpec) -> None:
        self.canonical = canonical

    def create_module(self, spec: ModuleSpec) -> None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        # Replace the placeholder, preserving the canonical module's metadata.
        sys.modules[module.__name__] = import_module(self.canonical.name)

    def get_code(self, fullname: str) -> CodeType | None:
        # runpy (-m) needs code rather than exec_module, including for the CLI.
        loader = self.canonical.loader
        if isinstance(loader, InspectLoader):
            return loader.get_code(self.canonical.name)
        return None


class _AliasFinder(MetaPathFinder):
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
            raise ModuleNotFoundError(f"No module named {fullname!r}", name=fullname)
        return spec_from_loader(fullname, _AliasLoader(canonical),
                                is_package=canonical.submodule_search_locations is not None)


_provider = _other_provider()
if _provider is not None:
    sys.meta_path[:] = [finder for finder in sys.meta_path if not _is_alias_finder(finder)]
    _module = module_from_spec(_provider)
    sys.modules[__name__] = _module
    try:
        if _provider.loader is not None:
            _provider.loader.exec_module(_module)
    except BaseException:
        sys.modules.pop(__name__, None)
        raise
else:
    _module = import_module("trustedrouter")
    if not any(_is_alias_finder(finder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _AliasFinder())
    sys.modules[__name__] = _module
