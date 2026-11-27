"""Streaming file hashing and checksum verification."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import string
from collections.abc import Iterable, Iterator
from typing import Optional

ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
DEFAULT_ALGORITHMS = ("sha256",)
CHUNK_SIZE = 1024 * 1024  # 1 MiB

_HEX_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_HEXDIGITS = frozenset(string.hexdigits)


class ChecksumFormatError(ValueError):
    """Raised for malformed expected hashes or checksum files."""


def _new_hasher(name: str):
    if name not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm {name!r}; choose from {', '.join(ALGORITHMS)}")
    try:  # MD5/SHA-1 are for checksum matching only, not security.
        return hashlib.new(name, usedforsecurity=False)
    except TypeError:  # pragma: no cover - very old OpenSSL builds
        return hashlib.new(name)


def hash_file(path: str, algorithms: Iterable[str] = DEFAULT_ALGORITHMS) -> dict[str, str]:
    """Hash ``path`` with every algorithm in one pass. Returns {algorithm: hexdigest}."""
    hashers = {name: _new_hasher(name) for name in dict.fromkeys(algorithms)}
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            for h in hashers.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


def parse_expected(value: str) -> tuple[str, str]:
    """Parse ``[algo:]hexdigest``. Returns (algorithm, lowercase digest)."""
    value = value.strip()
    algo: Optional[str] = None
    if ":" in value:
        algo, value = (part.strip() for part in value.split(":", 1))
        algo = algo.lower().replace("-", "")
        if algo not in ALGORITHMS:
            raise ChecksumFormatError(f"unsupported algorithm {algo!r}")
    value = value.lower()
    if not value or not set(value) <= _HEXDIGITS:
        raise ChecksumFormatError("expected hash must be hexadecimal")
    guessed = _HEX_LENGTHS.get(len(value))
    if guessed is None:
        raise ChecksumFormatError(
            f"hash length {len(value)} does not match md5/sha1/sha256/sha512"
        )
    if algo and algo != guessed:
        raise ChecksumFormatError(f"hash length {len(value)} does not fit {algo}")
    return guessed, value


def digests_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.lower(), b.lower())


# GNU coreutils:  "<hex>  name"  or  "<hex> *name"
_GNU_LINE = re.compile(r"^\\?(?P<hash>[0-9a-fA-F]+) [ *](?P<name>.+)$")
# BSD / `shasum --tag`:  "SHA256 (name) = <hex>"
_BSD_LINE = re.compile(r"^(?P<algo>[A-Za-z0-9-]+) ?\((?P<name>.+)\) ?= ?(?P<hash>[0-9a-fA-F]+)$")


def parse_checksum_file(path: str) -> Iterator[tuple[str, str, str]]:
    """Yield (file path, algorithm, digest) from a sha256sum/md5sum/BSD-style file.

    Relative paths are resolved against the checksum file's directory.
    """
    base = os.path.dirname(os.path.abspath(path))
    with open(path, encoding="utf-8-sig") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.rstrip("\r\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            m = _BSD_LINE.match(line) or _GNU_LINE.match(line)
            if not m:
                raise ChecksumFormatError(f"{path}:{lineno}: unrecognised checksum line")
            digest = m.group("hash")
            algo_hint = m.groupdict().get("algo")
            try:
                algo, digest = parse_expected(f"{algo_hint}:{digest}" if algo_hint else digest)
            except ChecksumFormatError as e:
                raise ChecksumFormatError(f"{path}:{lineno}: {e}") from e
            name = m.group("name")
            yield os.path.normpath(os.path.join(base, name)), algo, digest
