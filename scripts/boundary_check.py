"""Small, stdlib-only boundary rules supplementing strict mypy and Ruff.

This is a syntactic gate, not a claim of whole-program taint analysis. Decode
results must enter as object (so mypy requires narrowing), casts cannot replace
proof, consumed wire fields cannot be coerced inline, and Headers must survive
copies. The only exemptions below describe existing non-wire serialization.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

# These functions serialize SDK-owned telemetry or display an error; they do
# not authenticate, verify trust material, or parse inference response fields.
_SCALAR_EXEMPTIONS = {
    "_errors.py": {"_error_message"},
    "_telemetry.py": {
        "_wire_attempt", "_wire_event", "_drop_buffered_event_locked",
        "_select_batch_locked", "_remove_selected_locked", "_sample_reason", "_finish",
    },
    "_transport.py": {"stream_events", "astream_events"},
}


def findings(path: Path) -> list[str]:
    source = path.read_text()
    tree = ast.parse(source)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    errors: list[str] = []

    def report(node: ast.AST, code: str, message: str) -> None:
        errors.append(f"{path}:{getattr(node, 'lineno', 1)}: {code} {message}")

    def function(node: ast.AST) -> str:
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node.name
        return ""

    plain_headers: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            annotation = ast.unparse(node.annotation)
            if "headers" in node.arg and ("dict[" in annotation or "Mapping[" in annotation):
                plain_headers.add((function(node), node.arg))
        if isinstance(node, ast.Assign) and (
            isinstance(node.value, ast.Dict)
            or (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "dict")
        ):
            for target in node.targets:
                if isinstance(target, ast.Name) and "headers" in target.id:
                    plain_headers.add((function(node), target.id))
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if "headers" in node.target.id and "dict[" in ast.unparse(node.annotation):
                plain_headers.add((function(node), node.target.id))
    for node in ast.walk(tree):
        base = None
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            base = node.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"get", "update"}:
                base = node.func.value
        elif isinstance(node, ast.Compare) and any(
            isinstance(op, (ast.In, ast.NotIn)) for op in node.ops
        ):
            base = node.comparators[0]
        if isinstance(base, ast.Name) and (function(node), base.id) in plain_headers:
            if path.name == "session.py" and function(node) in {
                "_read_http_response", "_connection_close_requested",
            }:
                continue  # Wire parser lowercases names and rejects duplicate framing fields.
            report(node, "BND003", "Read mapping headers through the case-insensitive helper")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = (node.func.id if isinstance(node.func, ast.Name)
                else node.func.attr if isinstance(node.func, ast.Attribute) else "")
        if name == "cast":
            report(node, "BND002", "Use runtime narrowing, not a typing cast at a boundary")
        if name in {"json", "loads"}:
            parent = parents.get(node)
            if not (isinstance(parent, ast.AnnAssign)
                    and isinstance(parent.annotation, ast.Name)
                    and parent.annotation.id == "object"):
                report(node, "BND001", "Decode into an annotated object before narrowing")
        if name in {"str", "int", "bool"} and node.args:
            has_field = any(
                isinstance(child, ast.Subscript)
                or (isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                and child.func.attr == "get")
                for child in ast.walk(node.args[0])
            )
            if has_field and function(node) not in _SCALAR_EXEMPTIONS.get(path.name, set()):
                # Raw HTTP Content-Length is a string and its numeric parse is
                # explicitly translated to AttestationVerificationError.
                if path.name == "session.py" and function(node) == "_read_http_response":
                    continue
                report(node, "BND002", "Narrow a consumed field before scalar conversion")
        if name == "dict" and node.args and "headers" in ast.unparse(node.args[0]).lower():
            if path.name == "_requests.py" and function(node) == "_broadcast_destination_body":
                continue  # Producer's JSON configuration object, not an HTTP header store.
            report(node, "BND003", "Copy HTTP headers with httpx.Headers to preserve repeats")
    for number, line in enumerate(source.splitlines(), 1):
        if re.search(r'#\s*(?:ruff:\s*)?noqa\b', line, re.I) and not re.search(
            r'noqa:\s*[A-Z]+\d+(?:\s*,\s*[A-Z]+\d+)*\s+(?:--\s*)?\S', line
        ):
            errors.append(f"{path}:{number}: BND004 noqa requires specific rules and a reason")
    return errors


def main() -> int:
    paths = [Path(arg) for arg in sys.argv[1:]] or sorted(Path("src/trustedrouter").glob("*.py"))
    errors = [message for path in paths for message in findings(path)]
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Boundary rules passed ({len(paths)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
