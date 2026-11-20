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
        sentinel = server.sentinel = object()
        for _ in range(2):
            assert importlib.reload(server) is server
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


def test_legacy_provider_loader() -> None:
    assert run_code('''
        import importlib
        import sys
        import types
        import warnings
        from importlib.machinery import ModuleSpec
        class LegacyLoader:
            def load_module(self, fullname):
                module = sys.modules.setdefault(fullname, types.ModuleType(fullname))
                module.marker = "legacy"
                return module
        class EditableFinder:
            def find_spec(self, fullname, path=None, target=None):
                if fullname in ("legacy_control", "trusted_router"):
                    return ModuleSpec(fullname, LegacyLoader(), is_package=True)
        sys.meta_path.append(EditableFinder())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ImportWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                import legacy_control
            except ImportError:
                print("legacy loaders unsupported")
            else:
                import trusted_router
                assert trusted_router.marker == legacy_control.marker == "legacy"
                assert importlib.reload(trusted_router) is trusted_router
    ''') in ("", "legacy loaders unsupported\n")


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
