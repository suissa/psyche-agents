from __future__ import annotations

import ctypes
import os
from pathlib import Path

FLAG_PROMPT_INJECTION = 1
FLAG_CONTROL_BYTES = 2

_PATTERNS = (
    b"ignore previous instructions",
    b"ignore all previous instructions",
    b"reveal system prompt",
    b"show the system prompt",
    b"disable safeguards",
    b"bypass safety",
    b"act as developer",
    b"override system instructions",
)


def scan_python(text: str) -> int:
    """Conservative lexical pre-filter; this is not a complete injection detector."""
    data = text.encode("utf-8", errors="replace")
    flags = 0
    lowered = data.lower()
    if any(pattern in lowered for pattern in _PATTERNS):
        flags |= FLAG_PROMPT_INJECTION
    if any(byte < 32 and byte not in (9, 10, 13) for byte in data):
        flags |= FLAG_CONTROL_BYTES
    return flags


class ZigGuard:
    """Use the Zig C-ABI scanner when configured, otherwise use the Python fallback.

    An explicitly configured but unloadable native library is an error: silently
    falling back in that case could hide a broken production deployment.
    """

    def __init__(self, library_path: str | None = None) -> None:
        configured = library_path or os.getenv("PSYCHE_GUARD_LIB")
        self._native = None
        self.backend = "python"
        if configured:
            path = Path(configured)
            library = ctypes.CDLL(str(path))
            function = library.psyche_scan_input
            function.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
            function.restype = ctypes.c_uint32
            self._native = function
            self.backend = "zig"

    def scan(self, text: str) -> int:
        if self._native is None:
            return scan_python(text)
        encoded = text.encode("utf-8", errors="replace")
        buffer = ctypes.create_string_buffer(encoded, len(encoded) + 1)
        pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        return int(self._native(pointer, len(encoded)))
