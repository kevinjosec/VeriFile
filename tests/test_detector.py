import sys

import pytest
from conftest import PDF, PE, PNG

from verifile.detector import DetectionError, detect_file_type, libmagic_available, resolve_backend

EXECUTABLE_MIMES = (
    "application/vnd.microsoft.portable-executable",
    "application/x-executable",
    "application/x-mach-binary",
)


@pytest.mark.parametrize(
    ("content", "mime"),
    [
        (PNG, "image/png"),
        (PDF, "application/pdf"),
        (PE, "application/vnd.microsoft.portable-executable"),
        (b"\x7fELF\x02\x01\x01" + b"\x00" * 64, "application/x-executable"),
        (b"\xcf\xfa\xed\xfe" + b"\x00" * 64, "application/x-mach-binary"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 64, "application/java-vm"),
        (b"hello world\nsecond line\n", "text/plain"),
        ("héllo wörld\n".encode(), "text/plain"),
        (b"#!/usr/bin/env python3\nprint(1)\n", "text/x-python"),
        (b"#!/bin/bash\necho hi\n", "text/x-shellscript"),
        (b"@echo off\r\necho hi\r\n", "text/x-msdos-batch"),
        (b"", "inode/x-empty"),
        (bytes(range(256)) * 4, "application/octet-stream"),
    ],
)
def test_puremagic_backend(make_file, content, mime):
    detection = detect_file_type(make_file("a.bin", content), backend="puremagic")
    assert detection.mime == mime
    assert detection.backend == "puremagic"


def test_real_executable_detected_by_puremagic(make_file):
    """Regression: puremagic ranks obscure formats above PE for real executables."""
    with open(sys.executable, "rb") as f:
        content = f.read()
    detection = detect_file_type(make_file("holiday.jpg", content), backend="puremagic")
    assert detection.mime in EXECUTABLE_MIMES


def test_auto_backend_always_resolves():
    assert resolve_backend("auto") in ("libmagic", "puremagic")


def test_libmagic_request_without_libmagic_is_clear_error():
    if libmagic_available():
        pytest.skip("libmagic is installed here")
    with pytest.raises(DetectionError, match="libmagic"):
        resolve_backend("libmagic")


def test_unknown_backend_rejected():
    with pytest.raises(ValueError):
        resolve_backend("nope")
