"""Import contracts run in fresh interpreters, never changing pytest's imports."""
from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import textwrap
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def run_python(args: list[str], *, paths: list[Path] | None = None) -> str:
    # -S omits editable .pth entries from the parent checkout when the mutation
    # harness runs a temporary source copy. Keep its installed dependencies.
    search = [*(paths or [SRC]), Path(sysconfig.get_path("purelib")),
              Path(sysconfig.get_path("platlib"))]
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(map(str, search)),
               PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(  # noqa: S603 -- Test-owned interpreter argv, no shell.
        [sys.executable, "-S", *args], env=env, cwd=ROOT, capture_output=True,
        text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stderr == ""
    return result.stdout


def run_code(code: str, *args: str) -> str:
    return run_python(["-c", textwrap.dedent(code), *args])


@pytest.mark.parametrize("first", ["trusted_router", "trustedrouter"])
def test_module_identity(first: str) -> None:
    assert run_code('''
        import importlib
        import sys
        first = sys.argv[1]
        importlib.import_module(first)
        import trusted_router
        import trustedrouter
        assert trusted_router is trustedrouter
        from trusted_router import TrustedRouter, AsyncTrustedRouter
        assert TrustedRouter is trustedrouter.TrustedRouter
        assert AsyncTrustedRouter is trustedrouter.AsyncTrustedRouter
        for suffix in ("client", "models", "attestation", "__main__"):
            # Exercise both submodule import orders as well as top-level orders.
            a = importlib.import_module(first + "." + suffix)
            other = "trustedrouter" if first == "trusted_router" else "trusted_router"
            b = importlib.import_module(other + "." + suffix)
            assert a is b, suffix
            assert a.__spec__.name == "trustedrouter." + suffix
            assert a.__name__ == "trustedrouter." + suffix
            assert sys.modules["trusted_router." + suffix] is a
            assert sys.modules["trustedrouter." + suffix] is a
        import trusted_router.client
        import trustedrouter.client
        assert trusted_router.client is trustedrouter.client
        from trusted_router.models import ChatMessage
        assert isinstance(ChatMessage(role="user", content="hello"), trustedrouter.ChatMessage)
        from trusted_router.attestation import AttestationVerificationError
        assert isinstance(AttestationVerificationError("test"),
                          trustedrouter.AttestationVerificationError)
        assert trusted_router.__main__.main(["--version"]) == 0
    ''', first) == "trustedrouter 0.10.0\n"


def test_missing_submodule() -> None:
    assert run_code('''
        import importlib
        import sys
        for name in ("trusted_router.no_such_module", "trustedrouter.no_such_module"):
            try:
                importlib.import_module(name)
            except ModuleNotFoundError as exc:
                assert exc.name == name
                assert name in str(exc)
                assert name not in sys.modules
            else:
                raise AssertionError("missing module imported")
    ''') == ""


def test_finder_scope_and_reimport() -> None:
    assert run_code('''
        import importlib
        import sys
        import trusted_router
        import trustedrouter
        finders = [f for f in sys.meta_path if getattr(f, "_trusted_router_alias", False)]
        assert len(finders) == 1
        finder = finders[0]
        for name in ("os", "unrelated", "trustedrouter.models", "trusted_router_extra.x"):
            assert finder.find_spec(name) is None
        for _ in range(2):
            assert importlib.reload(trusted_router) is trustedrouter
            del sys.modules["trusted_router"]
            assert finder.find_spec("trusted_router.models") is None
            assert importlib.import_module("trusted_router") is trustedrouter
            current = [f for f in sys.meta_path if getattr(f, "_trusted_router_alias", False)]
            assert current == finders
        models = importlib.import_module("trusted_router.models")
        assert importlib.reload(models) is trustedrouter.models
    ''') == ""


@pytest.fixture
def real_package(tmp_path: Path) -> Path:
    package = tmp_path / "trusted_router"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import sys\nfrom . import serve\nmarker = 'server'\n"
        "assert sys.modules[__name__].serve is serve\n"
    )
    (package / "serve.py").write_text(
        "marker = 'serve'\nif __name__ == '__main__':\n    print('server serve')\n"
    )
    (package / "__main__.py").write_text("print('server main')\n")
    return tmp_path


@pytest.mark.parametrize("position", ["before", "after"])
def test_step_aside(real_package: Path, position: str) -> None:
    assert run_code('''
        import sys
        from pathlib import Path
        root, position = sys.argv[1:]
        if position == "before":
            sys.path.insert(0, root)
        else:
            sys.path.append(root)
        import trusted_router
        assert trusted_router.marker == "server"
        assert Path(trusted_router.__file__).parent == Path(root) / "trusted_router"
        import trusted_router.serve
        assert trusted_router.serve.marker == "serve"
        import trustedrouter
        assert trusted_router is not trustedrouter
        assert trustedrouter.TrustedRouter
        assert not any(getattr(f, "_trusted_router_alias", False) for f in sys.meta_path)
    ''', str(real_package), position) == ""


@pytest.mark.parametrize("position", ["before", "after"])
@pytest.mark.parametrize("module", ["trusted_router.serve", "trusted_router"])
def test_step_aside_module_execution(real_package: Path, position: str, module: str) -> None:
    # Avoid importing serve in __init__ for -m, just as a real CLI package would.
    (real_package / "trusted_router/__init__.py").write_text("marker = 'server'\n")
    paths = [real_package, SRC] if position == "before" else [SRC, real_package]
    expected = "server serve\n" if module.endswith(".serve") else "server main\n"
    assert run_python(["-m", module], paths=paths) == expected


def test_step_aside_error(tmp_path: Path) -> None:
    package = tmp_path / "trusted_router"
    package.mkdir()
    (package / "__init__.py").write_text("import builtins\nraise builtins.alias_error\n")
    assert run_code('''
        import builtins
        import sys
        builtins.alias_error = RuntimeError("server import failed")
        sys.path.append(sys.argv[1])
        try:
            import trusted_router
        except RuntimeError as exc:
            assert exc is builtins.alias_error
            assert "trusted_router" not in sys.modules
            assert "trustedrouter" not in sys.modules
        else:
            raise AssertionError("server error swallowed")
    ''', str(tmp_path)) == ""


def test_meta_path_provider(real_package: Path) -> None:
    assert run_code('''
        import sys
        from importlib.machinery import PathFinder
        class EditableFinder:
            @staticmethod
            def find_spec(fullname, path=None, target=None):
                if fullname == "trusted_router":
                    return PathFinder.find_spec(fullname, [sys.argv[1]])
        sys.meta_path.append(EditableFinder)
        import trusted_router
        assert trusted_router.marker == "server"
        import trusted_router.serve
        assert trusted_router.serve.marker == "serve"
        assert "trustedrouter" not in sys.modules
    ''', str(real_package)) == ""


def test_reload_passes_the_target_to_other_finders(tmp_path: Path) -> None:
    # A finder may answer differently for a reload (target supplied). With the
    # alias absent, reload executes its second answer in the same module object.
    for name in ("first", "second"):
        package = tmp_path / name / "trusted_router"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text(f"marker = {name!r}\n")
    assert run_code('''
        import importlib
        import sys
        from importlib.machinery import PathFinder
        from pathlib import Path
        root = Path(sys.argv[1])
        class TargetAwareFinder:
            @staticmethod
            def find_spec(fullname, path=None, target=None):
                if fullname == "trusted_router":
                    chosen = "first" if target is None else "second"
                    return PathFinder.find_spec(fullname, [str(root / chosen)])
        sys.meta_path.append(TargetAwareFinder)
        import trusted_router
        assert trusted_router.marker == "first"
        reloaded = importlib.reload(trusted_router)
        assert reloaded is trusted_router
        assert trusted_router.marker == "second"
        assert Path(trusted_router.__file__).parent.parent.name == "second"
        assert "trustedrouter" not in sys.modules
    ''', str(tmp_path)) == ""


def test_replaced_path_finder(real_package: Path) -> None:
    assert run_code('''
        import sys
        from importlib.machinery import PathFinder
        class WrappedPathFinder:
            @staticmethod
            def find_spec(fullname, path=None, target=None):
                return PathFinder.find_spec(fullname, path, target)
        sys.meta_path = [WrappedPathFinder if f is PathFinder else f for f in sys.meta_path]
        sys.path.append(sys.argv[1])
        import trusted_router
        assert trusted_router.marker == "server"
        import trusted_router.serve
        assert trusted_router.serve.marker == "serve"
    ''', str(real_package)) == ""


def test_alias_origin_and_symlink_are_not_other_providers(tmp_path: Path) -> None:
    link = tmp_path / "linked-src"
    link.symlink_to(SRC, target_is_directory=True)
    assert run_code('''
        import sys
        from importlib.machinery import PathFinder
        class SamePackageFinder:
            @staticmethod
            def find_spec(fullname, path=None, target=None):
                if fullname == "trusted_router":
                    return PathFinder.find_spec(fullname, [sys.argv[1]])
        sys.path.append(sys.argv[1])
        sys.meta_path.append(SamePackageFinder)
        import trusted_router
        import trustedrouter
        assert trusted_router is trustedrouter
    ''', str(link)) == ""


@pytest.mark.parametrize("position", ["before", "after"])
def test_namespace_directory_does_not_hide_the_sdk(tmp_path: Path, position: str) -> None:
    # A folder named trusted_router with no __init__ (a project directory, a
    # clone) loses to a regular package in ordinary imports; the alias agrees.
    package = tmp_path / "trusted_router"
    package.mkdir()
    (package / "serve.py").write_text("marker = 'namespace'\n")
    assert run_code('''
        import sys
        if sys.argv[2] == "before":
            sys.path.insert(0, sys.argv[1])
        else:
            sys.path.append(sys.argv[1])
        import trusted_router
        import trustedrouter
        assert trusted_router is trustedrouter
        from trusted_router import TrustedRouter
        assert TrustedRouter is trustedrouter.TrustedRouter
    ''', str(tmp_path), position) == ""


def test_reimport_steps_aside(real_package: Path) -> None:
    (real_package / "trusted_router/__init__.py").write_text(
        "from . import models\nassert models.marker == 'server models'\nmarker = 'server'\n"
    )
    (real_package / "trusted_router/models.py").write_text("marker = 'server models'\n")
    assert run_code('''
        import sys
        import trusted_router.models
        import trusted_router.client
        import trustedrouter.models
        sdk_models = trustedrouter.models
        finder = next(f for f in sys.meta_path if getattr(f, "_trusted_router_alias", False))
        del sys.modules["trusted_router"]
        sys.path.append(sys.argv[1])
        import trusted_router
        assert trusted_router.marker == "server"
        assert trusted_router.models.__name__ == "trusted_router.models"
        assert trusted_router.models is not sdk_models
        assert trustedrouter.models is sdk_models
        assert "trusted_router.client" not in sys.modules
        assert finder not in sys.meta_path
        assert finder.find_spec("trusted_router.serve") is None
    ''', str(real_package)) == ""


@pytest.mark.parametrize("fail_first", [False, True])
def test_concurrent_server_initialization(real_package: Path, fail_first: bool) -> None:
    (real_package / "trusted_router/__init__.py").write_text(
        "import builtins\n"
        "builtins.entered.set()\n"
        "assert builtins.release.wait(5)\n"
        "if builtins.fail_first:\n"
        "    builtins.fail_first = False\n"
        "    raise builtins.original_error\n"
        "ready = True\n"
    )
    assert run_code('''
        import builtins
        import importlib
        import sys
        import threading
        builtins.entered = threading.Event()
        builtins.release = threading.Event()
        builtins.fail_first = sys.argv[2] == "True"
        builtins.original_error = RuntimeError("original server exception")
        sys.path.append(sys.argv[1])
        modules, errors = [], []
        attempted, completed = threading.Event(), threading.Event()
        def first():
            try:
                modules.append(importlib.import_module("trusted_router"))
            except BaseException as exc:
                errors.append(exc)
        def second():
            attempted.set()
            first()
            completed.set()
        a = threading.Thread(target=first)
        b = threading.Thread(target=second)
        a.start()
        assert builtins.entered.wait(5)
        b.start()
        assert attempted.wait(5)
        try:
            assert not completed.wait(0.2), "concurrent import bypassed the module lock"
            assert sys.modules["trusted_router"].__spec__._initializing
        finally:
            builtins.release.set()
            a.join(5)
            b.join(5)
        assert not a.is_alive() and not b.is_alive()
        assert errors == ([builtins.original_error] if sys.argv[2] == "True" else [])
        assert all(m is sys.modules["trusted_router"] and m.ready for m in modules)
        assert len(modules) == (1 if errors else 2)
        assert not modules[0].__spec__._initializing
        assert "trustedrouter" not in sys.modules
    ''', str(real_package), str(fail_first)) == ""


def test_second_shim_copy(real_package: Path, tmp_path: Path) -> None:
    copy = tmp_path / "second-install"
    shutil.copytree(SRC / "trusted_router", copy / "trusted_router")
    assert run_python(["-c", "import trusted_router; assert trusted_router.marker == 'server'"],
                      paths=[SRC, copy, real_package]) == ""


def test_case_variant_shim_path(real_package: Path, tmp_path: Path) -> None:
    copy = tmp_path / "MixedCaseShim"
    shutil.copytree(SRC / "trusted_router", copy / "trusted_router")
    variant = tmp_path / "mIXEDcASEsHIM"
    if not variant.exists() or not os.path.samefile(copy, variant):
        pytest.skip("filesystem is case sensitive")
    assert run_python(["-c", "import trusted_router; assert trusted_router.marker == 'server'"],
                      paths=[copy, variant, real_package, SRC]) == ""


def test_server_reload_identity_and_metadata(real_package: Path) -> None:
    assert run_code('''
        import importlib
        import sys
        from importlib.machinery import PathFinder
        sys.path.append(sys.argv[1])
        expected = PathFinder.find_spec("trusted_router", [sys.argv[1]])
        import trusted_router as server
        assert set(vars(server)) == {
            "__name__", "__doc__", "__package__", "__loader__", "__spec__", "__path__",
            "__file__", "__cached__", "__builtins__", "sys", "serve", "marker",
        }
        sentinel = server.sentinel = object()
        for _ in range(2):
            assert sys.modules["trusted_router"] is server
            assert server.sentinel is sentinel
            assert server.__name__ == server.__spec__.name == "trusted_router"
            assert server.__package__ == "trusted_router"
            assert server.__file__ == server.__spec__.origin == expected.origin
            assert list(server.__path__) == list(expected.submodule_search_locations)
            assert server.__loader__ is server.__spec__.loader
            assert type(server.__loader__) is type(expected.loader)
            assert server.__loader__.path == expected.loader.path
            assert server.__cached__ == expected.cached
            assert server.serve.marker == "serve"
            assert importlib.reload(server) is server
    ''', str(real_package)) == ""


def test_ignored_sys_path_entries(real_package: Path) -> None:
    assert run_code('''
        import sys
        sys.path.extend([None, b"ignored", 42, "", "/does-not-exist"])
        sys.path.append(sys.argv[1])
        import trusted_router
        assert trusted_router.marker == "server"
    ''', str(real_package)) == ""


def test_legacy_finder_is_skipped(real_package: Path) -> None:
    assert run_code('''
        import sys
        from importlib.machinery import PathFinder
        class LegacyFinder:
            def find_module(self, fullname, path=None):
                return None
        class EditableFinder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "trusted_router":
                    return PathFinder.find_spec(fullname, [sys.argv[1]])
        sys.meta_path.extend([LegacyFinder(), EditableFinder()])
        import trusted_router
        assert trusted_router.marker == "server"
    ''', str(real_package)) == ""


@pytest.mark.parametrize("kind", ["get-code-error", "create-state", "legacy", "subclass",
                                  "locationless", "missing-origin"])
def test_unsupported_provider_is_ignored(real_package: Path, kind: str) -> None:
    assert run_code('''
        import sys
        from importlib.machinery import SourceFileLoader
        from importlib.util import spec_from_file_location
        class CustomLoader:
            def create_module(self, spec):
                from types import ModuleType
                module = ModuleType(spec.name)
                module.required_state = "server"
                return module
            def exec_module(self, module):
                module.marker = module.required_state
            def get_code(self, name):
                if sys.argv[2] == "get-code-error":
                    raise RuntimeError("optional inspection failed")
                return None
        class LegacyLoader:
            def load_module(self, name):
                raise AssertionError("unsupported loader executed")
        class SubclassLoader(SourceFileLoader):
            pass
        origin = sys.argv[1] + "/trusted_router/__init__.py"
        kind = sys.argv[2]
        loader = SourceFileLoader("trusted_router", origin)
        if kind in ("get-code-error", "create-state"):
            loader = CustomLoader()
        elif kind == "legacy":
            loader = LegacyLoader()
        elif kind == "subclass":
            loader = SubclassLoader("trusted_router", origin)
        spec = spec_from_file_location("trusted_router", origin, loader=loader,
                                      submodule_search_locations=[sys.argv[1]])
        if kind == "locationless":
            spec.has_location = False
        elif kind == "missing-origin":
            spec.origin = origin + ".missing"
        class Finder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "trusted_router":
                    return spec
        sys.meta_path.append(Finder())
        import trusted_router
        import trustedrouter
        assert trusted_router is trustedrouter
    ''', str(real_package), kind) == ""


@pytest.mark.parametrize("inspection", ["raises", "unexpected", "none", "execution-error"])
def test_standard_loader_code_inspection(real_package: Path, inspection: str) -> None:
    assert run_code('''
        import sys
        from importlib.machinery import PathFinder, SourceFileLoader
        spec = PathFinder.find_spec("trusted_router", [sys.argv[1]])
        assert type(spec.loader) is SourceFileLoader
        original = spec.loader.get_code
        error = RuntimeError("original provider error")
        calls = []
        def get_code(name):
            calls.append(name)
            if sys.argv[2] == "execution-error":
                raise error
            if len(calls) == 1:
                if sys.argv[2] == "raises":
                    raise error
                return object() if sys.argv[2] == "unexpected" else None
            return original(name)
        spec.loader.get_code = get_code
        class Finder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "trusted_router":
                    return spec
        sys.meta_path.append(Finder())
        try:
            import trusted_router
        except RuntimeError as exc:
            assert sys.argv[2] == "execution-error"
            assert exc is error
            assert "trusted_router" not in sys.modules
        else:
            assert sys.argv[2] != "execution-error"
            assert trusted_router.marker == "server"
        assert calls == ["trusted_router", "trusted_router"]
        assert "trustedrouter" not in sys.modules
    ''', str(real_package), inspection) == ""


@pytest.mark.parametrize("wrapper", ["exec-only", "lazy", "zip"])
def test_wrapped_shim_before_standard_provider(
    real_package: Path, tmp_path: Path, wrapper: str,
) -> None:
    archive = tmp_path / "second-shim.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.write(SRC / "trusted_router/__init__.py", "trusted_router/__init__.py")
    assert run_code('''
        import sys
        from importlib.machinery import PathFinder
        from importlib.util import LazyLoader
        spec = PathFinder.find_spec("trusted_router", [sys.argv[1]])
        original = spec.loader
        class Wrapper:
            def create_module(self, spec):
                return None
            def exec_module(self, module):
                original.exec_module(module)
        if sys.argv[3] == "exec-only":
            spec.loader = Wrapper()
        elif sys.argv[3] == "lazy":
            spec.loader = LazyLoader(original)
        class WrappedFinder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "trusted_router":
                    return spec
        class RealFinder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "trusted_router":
                    return PathFinder.find_spec(fullname, [sys.argv[2]])
        sys.meta_path.extend([WrappedFinder(), RealFinder()])
        import trusted_router
        assert trusted_router.marker == "server"
        assert "trustedrouter" not in sys.modules
    ''', str(archive), str(real_package), wrapper) == ""


@pytest.mark.parametrize("server", [False, True])
def test_raising_foreign_finder(real_package: Path, server: bool) -> None:
    assert run_code('''
        import sys
        from importlib.machinery import PathFinder
        class RaisingFinder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "trusted_router":
                    raise RuntimeError("foreign discovery failed")
        class RealFinder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "trusted_router" and sys.argv[2] == "True":
                    return PathFinder.find_spec(fullname, [sys.argv[1]])
        sys.meta_path.extend([RaisingFinder(), RealFinder()])
        import trusted_router
        if sys.argv[2] == "True":
            assert trusted_router.marker == "server"
            assert "trustedrouter" not in sys.modules
        else:
            import trustedrouter
            assert trusted_router is trustedrouter
    ''', str(real_package), str(server)) == ""


@pytest.mark.parametrize("bytecode", [False, True])
def test_standard_module_metadata(tmp_path: Path, bytecode: bool) -> None:
    source = tmp_path / "trusted_router.py"
    source.write_text("marker = 'server'\n")
    assert run_code('''
        import importlib
        import py_compile
        import sys
        from pathlib import Path
        from importlib.machinery import PathFinder
        from importlib.util import module_from_spec
        source = Path(sys.argv[1]) / "trusted_router.py"
        if sys.argv[2] == "True":
            py_compile.compile(str(source), cfile=str(source) + "c", doraise=True)
            source.unlink()
        sys.path.append(sys.argv[1])
        expected = PathFinder.find_spec("trusted_router", [sys.argv[1]])
        control = module_from_spec(expected)
        expected.loader.exec_module(control)
        import trusted_router
        for _ in range(2):
            assert set(vars(trusted_router)) == set(vars(control))
            for name in ("__name__", "__file__", "__cached__", "__package__"):
                assert getattr(trusted_router, name) == getattr(control, name)
            assert trusted_router.__loader__ is trusted_router.__spec__.loader
            assert trusted_router.__spec__.origin == expected.origin
            assert trusted_router.marker == "server"
            assert importlib.reload(trusted_router) is trusted_router
        assert "trustedrouter" not in sys.modules
    ''', str(tmp_path), str(bytecode)) == ""


@pytest.mark.parametrize("missing", ["_exec", "_initializing"])
@pytest.mark.parametrize("server", [False, True])
def test_missing_importlib_protocol(real_package: Path, missing: str, server: bool) -> None:
    assert run_code('''
        import sys
        from importlib import _bootstrap
        from importlib.machinery import PathFinder
        original = _bootstrap._exec
        class Finder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "trusted_router":
                    if sys.argv[2] == "_exec":
                        del _bootstrap._exec
                    else:
                        del sys.modules[fullname].__spec__._initializing
                    if sys.argv[3] == "True":
                        return PathFinder.find_spec(fullname, [sys.argv[1]])
        sys.meta_path.append(Finder())
        try:
            try:
                import trusted_router
            except ImportError as exc:
                assert sys.argv[3] == "True"
                assert "trusted_router handoff requires" in str(exc)
                assert sys.argv[2] in str(exc)
                assert "trusted_router" not in sys.modules
                assert "trustedrouter" not in sys.modules
            else:
                assert sys.argv[3] == "False"
                import trustedrouter
                assert trusted_router is trustedrouter
        finally:
            _bootstrap._exec = original
    ''', str(real_package), missing, str(server)) == ""


@pytest.mark.parametrize("server", [False, True])
def test_zip_provider_is_ignored(real_package: Path, tmp_path: Path, server: bool) -> None:
    archive = tmp_path / "server.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("trusted_router/__init__.py", "raise AssertionError('zip provider ran')")
    code = ("import trusted_router; assert trusted_router.marker == 'server'" if server else
            "import trusted_router, trustedrouter; assert trusted_router is trustedrouter")
    paths = [SRC, archive, real_package] if server else [SRC, archive]
    assert run_python(["-c", code], paths=paths) == ""


@pytest.mark.parametrize("module", ["trusted_router", "trusted_router.__main__"])
def test_zip_cli(tmp_path: Path, module: str) -> None:
    archive = tmp_path / "sdk.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        for path in SRC.rglob("*.py"):
            zipped.write(path, path.relative_to(SRC))
    assert run_python(["-m", module, "--version"], paths=[archive]) == "trustedrouter 0.10.0\n"


def test_missing_submodule_spec() -> None:
    assert run_code('''
        import importlib.util
        import sys
        assert importlib.util.find_spec("trusted_router.missing") is None
        assert importlib.util.find_spec("trustedrouter.missing") is None
        class LaterFinder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "trusted_router.missing":
                    return importlib.machinery.ModuleSpec(fullname, None)
        sys.meta_path.append(LaterFinder())
        assert importlib.util.find_spec("trusted_router.missing").name == "trusted_router.missing"
    ''') == ""


@pytest.mark.parametrize("module", ["trustedrouter", "trusted_router", "trusted_router.__main__"])
def test_cli(module: str) -> None:
    assert run_python(["-m", module, "--version"]) == "trustedrouter 0.10.0\n"


def test_both_packages_configured() -> None:
    # The consumer release tests additionally build and inspect both artifacts.
    config = (ROOT / "pyproject.toml").read_text()
    for target, key in (("wheel", "packages"), ("sdist", "only-include")):
        match = re.search(rf"\[tool.hatch.build.targets.{target}\]\n{key} = (.+)", config)
        assert match is not None
        assert set(ast.literal_eval(match[1])) == {"src/trustedrouter", "src/trusted_router"}
