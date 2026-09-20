"""Case-insensitive reads for arbitrary string mappings, without re-encoding values."""
from collections.abc import Mapping


def _header(headers: Mapping[str, str], name: str) -> str | None:
    # Headers.items() already joins repeats. For a plain mapping, combine keys
    # that differ only in case so conflicting retry hints are never trusted.
    values = [value for key, value in headers.items() if key.lower() == name.lower()]
    return ", ".join(values) if values else None
