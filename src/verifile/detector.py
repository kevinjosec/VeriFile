"""Content-based file type detection.

Two backends are supported:

* ``libmagic`` via the optional ``python-magic`` package (most accurate, needs the
  native libmagic library installed on the system).
* ``puremagic``, a pure-Python signature database that works everywhere.

``auto`` uses libmagic when it is available and falls back to puremagic otherwise,
so the tool never crashes just because libmagic is missing.
"""

from __future__ import annotations

import codecs
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

from verifile.filetypes import EXTENSION_MIME, normalize_mime

BACKENDS = ("auto", "libmagic", "puremagic")
SNIFF_BYTES = 8192


class DetectionError(Exception):
    """Raised when a file's type cannot be determined."""


@dataclass(frozen=True)
class Detection:
    mime: Optional[str]
    description: Optional[str]
    backend: str

    def to_dict(self) -> dict:
        return {"mime": self.mime, "description": self.description, "backend": self.backend}


@lru_cache(maxsize=1)
def _load_libmagic():
    """Return the ``magic`` module if python-magic *and* libmagic are usable, else None."""
    try:
        import magic  # type: ignore[import-not-found]

        magic.from_buffer(b"\x89PNG\r\n\x1a\n", mime=True)  # smoke test the native lib
        return magic
    except Exception:  # ImportError, OSError, magic.MagicException, ...
        return None


def libmagic_available() -> bool:
    return _load_libmagic() is not None


def resolve_backend(requested: str = "auto") -> str:
    if requested not in BACKENDS:
        raise ValueError(f"unknown backend {requested!r}; choose from {', '.join(BACKENDS)}")
    if requested == "auto":
        return "libmagic" if libmagic_available() else "puremagic"
    if requested == "libmagic" and not libmagic_available():
        raise DetectionError(
            "libmagic backend requested but not available. "
            "Install it with 'pip install verifile[libmagic]' plus the system libmagic "
            "library (apt install libmagic1 / brew install libmagic)."
        )
    return requested


def detect_file_type(path: str, backend: str = "auto") -> Detection:
    """Detect the real type of ``path`` from its content."""
    backend = resolve_backend(backend)
    if os.path.getsize(path) == 0:
        return Detection("inode/x-empty", "empty file", backend)
    if backend == "libmagic":
        return _detect_libmagic(path)
    return _detect_puremagic(path)


def _detect_libmagic(path: str) -> Detection:
    magic = _load_libmagic()
    try:
        mime = magic.from_file(path, mime=True)
        description = magic.from_file(path)
    except OSError:
        raise
    except Exception as e:
        raise DetectionError(f"libmagic failed: {e}") from e
    return Detection(normalize_mime(mime), description or None, "libmagic")


def _detect_puremagic(path: str) -> Detection:
    import puremagic

    with open(path, "rb") as f:
        head = f.read(SNIFF_BYTES)

    # Executables are the security-critical case, so check their structure ourselves
    # rather than relying on puremagic's ranking (which buries PE under obscure formats).
    exe_mime, exe_desc = _sniff_executable(head)
    if exe_mime:
        return Detection(exe_mime, exe_desc, "puremagic")

    try:
        matches = puremagic.magic_file(path)
    except (puremagic.PureError, ValueError):
        matches = []

    # Take the highest-confidence match that maps to a usable MIME type.
    for match in matches:
        mime = normalize_mime(match.mime_type)
        if mime in (None, "application/octet-stream"):
            # puremagic sometimes knows the format but not its MIME type.
            ext = (match.extension or "").lstrip(".").lower()
            mime = EXTENSION_MIME.get(ext)
        if not mime:
            continue
        if mime == "text/plain":
            # Newer puremagic recognises text but not what kind; refine it ourselves.
            refined, refined_desc = _sniff_text(head)
            if refined and refined != "text/plain":
                return Detection(refined, refined_desc, "puremagic")
        return Detection(mime, match.name or None, "puremagic")

    text_mime, text_desc = _sniff_text(head)
    if text_mime:
        return Detection(text_mime, text_desc, "puremagic")
    return Detection("application/octet-stream", "data (unrecognised binary)", "puremagic")


_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")


def _sniff_executable(head: bytes) -> tuple[Optional[str], Optional[str]]:
    """Recognise native executables by structure. Returns (mime, description)."""
    if head.startswith(b"MZ") and len(head) >= 64:
        pe_offset = int.from_bytes(head[0x3C:0x40], "little")
        if head[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            return "application/vnd.microsoft.portable-executable", "Windows PE executable"
        return "application/vnd.microsoft.portable-executable", "MS-DOS executable"
    if head.startswith(b"\x7fELF"):
        return "application/x-executable", "ELF executable"
    if head[:4] in _MACHO_MAGICS:
        return "application/x-mach-binary", "Mach-O executable"
    if head.startswith(b"\xca\xfe\xba\xbe") and len(head) >= 8:
        # Shared by universal Mach-O (small arch count) and Java classes (version >= 45).
        if int.from_bytes(head[4:8], "big") < 45:
            return "application/x-mach-binary", "Mach-O universal binary"
        return "application/java-vm", "Java class file"
    return None, None


_SHEBANGS = (
    (("python",), "text/x-python", "Python script"),
    (("node", "deno", "bun"), "text/javascript", "JavaScript script"),
    (("perl",), "text/x-perl", "Perl script"),
    (("ruby",), "text/x-ruby", "Ruby script"),
    (("php",), "text/x-php", "PHP script"),
    (("sh", "bash", "zsh", "dash", "ksh", "fish"), "text/x-shellscript", "shell script"),
)


def _sniff_text(head: bytes) -> tuple[Optional[str], Optional[str]]:
    """Heuristically decide whether ``head`` is text. Returns (mime, description)."""
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "text/plain", "UTF-16 text"
    if b"\x00" in head:
        return None, None
    try:
        text = codecs.getincrementaldecoder("utf-8")().decode(head, final=False)
    except UnicodeDecodeError:
        return None, None
    # Reject data that is mostly control characters even if it is valid UTF-8.
    controls = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\n\r\f\v\x1b")
    if text and controls / len(text) > 0.05:
        return None, None

    if text.startswith("#!"):
        interpreter = text[2:].split("\n", 1)[0].strip().replace("/usr/bin/env ", "")
        program = os.path.basename(interpreter.split(" ", 1)[0])
        for names, mime, desc in _SHEBANGS:
            if any(program == n or program.startswith(n) for n in names):
                return mime, desc
        return "text/plain", "script text"
    stripped = text.lstrip().lower()
    if stripped.startswith("@echo off"):
        return "text/x-msdos-batch", "DOS batch file"
    if stripped.startswith("<?xml"):
        return "application/xml", "XML document"
    if stripped.startswith(("<!doctype html", "<html")):
        return "text/html", "HTML document"
    return "text/plain", "text"
