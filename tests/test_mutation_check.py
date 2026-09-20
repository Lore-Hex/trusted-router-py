"""The proof runner must fail closed and restore bytes even on interruption."""
from __future__ import annotations

import runpy
import subprocess
from pathlib import Path

import pytest

_RUNNER = runpy.run_path(str(Path(__file__).parents[1] / "scripts/mutation_check.py"))


def test_mutation_restores_original_bytes_on_interruption(tmp_path) -> None:
    path = tmp_path / "source.py"
    original = b"first\r\nsecond\r\n"
    path.write_bytes(original)
    mutation = {"name": "proof", "file": "source.py", "before": "second", "after": "changed"}
    with pytest.raises(KeyboardInterrupt), _RUNNER["mutated"](tmp_path, mutation):
        assert path.read_bytes() == b"first\r\nchanged\r\n"
        raise KeyboardInterrupt
    assert path.read_bytes() == original


def test_stale_mutation_fails_without_touching_source(tmp_path) -> None:
    path = tmp_path / "source.py"
    path.write_bytes(b"original")
    mutation = {"name": "stale", "file": "source.py", "before": "absent", "after": "changed"}
    with pytest.raises(ValueError, match="STALE"), _RUNNER["mutated"](tmp_path, mutation):
        pytest.fail("stale mutation ran")
    assert path.read_bytes() == b"original"


@pytest.mark.parametrize("status,stdout", [(0, ""), (1, "collection problem"), (2, "FAILED test")])
def test_survivors_and_invalid_proofs_fail(status, stdout) -> None:
    result = subprocess.CompletedProcess([], status, stdout=stdout, stderr="")
    with pytest.raises(ValueError):
        _RUNNER["require_killed"](result, "probe")
