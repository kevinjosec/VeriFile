"""Compare what a file *claims* to be (its extension) with what it *is* (its content)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from verifile.filetypes import (
    EXECUTABLE_EXTS,
    OLE_MIMES,
    ZIP_CONTAINER_EXTS,
    expected_mime_for,
    extension_of,
    is_executable,
    is_textual,
    normalize_mime,
)

# Status values
MATCH = "match"            # extension and content agree
COMPATIBLE = "compatible"  # different labels for a legitimately compatible format
MISMATCH = "mismatch"      # extension lies about the content
UNKNOWN = "unknown"        # not enough information to judge
EMPTY = "empty"            # zero-byte file

# Severity values
NONE, LOW, MEDIUM, HIGH = "none", "low", "medium", "high"


@dataclass(frozen=True)
class Verdict:
    status: str
    severity: str
    reason: str
    expected_mime: Optional[str]

    @property
    def is_problem(self) -> bool:
        return self.status == MISMATCH

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate(path: str, detected_mime: Optional[str]) -> Verdict:
    ext = extension_of(path)
    expected = expected_mime_for(path)
    detected = normalize_mime(detected_mime)

    if detected == "inode/x-empty":
        return Verdict(EMPTY, NONE, "file is empty", expected)
    if not ext:
        if is_executable(detected):
            return Verdict(UNKNOWN, LOW, "no extension; content is executable", None)
        return Verdict(UNKNOWN, NONE, "file has no extension to compare against", None)
    if detected in (None, "application/octet-stream"):
        if is_textual(expected):
            return Verdict(MISMATCH, MEDIUM,
                           f".{ext} should be text but content is unrecognised binary", expected)
        return Verdict(UNKNOWN, NONE, "content type could not be identified", expected)

    executable_content = is_executable(detected)
    executable_ext = ext in EXECUTABLE_EXTS

    if executable_content and not executable_ext:
        return Verdict(MISMATCH, HIGH,
                       f"executable content ({detected}) disguised as .{ext}", expected)
    if expected is None:
        return Verdict(UNKNOWN, NONE, f"no known type for extension .{ext}", None)
    if detected == expected:
        return Verdict(MATCH, NONE, "content matches extension", expected)
    if executable_content and executable_ext:
        return Verdict(COMPATIBLE, NONE, "executable content with executable extension", expected)
    if detected == "application/zip" and ext in ZIP_CONTAINER_EXTS:
        return Verdict(COMPATIBLE, NONE, f".{ext} is a ZIP-based format", expected)
    if detected in OLE_MIMES and expected in OLE_MIMES:
        return Verdict(COMPATIBLE, NONE, f".{ext} is an OLE compound-document format", expected)
    if is_textual(detected) and is_textual(expected):
        # Content sniffing cannot reliably tell text formats apart (CSV vs TXT vs MD ...).
        return Verdict(COMPATIBLE, NONE, "both are text formats", expected)
    if is_textual(expected) and not is_textual(detected):
        return Verdict(MISMATCH, MEDIUM,
                       f".{ext} should be text but content is {detected}", expected)
    if detected.split("/")[0] == expected.split("/")[0] and detected.split("/")[0] in (
        "image", "audio", "video",
    ):
        return Verdict(MISMATCH, LOW,
                       f"content is {detected}, extension suggests {expected}", expected)
    return Verdict(MISMATCH, MEDIUM,
                   f"content is {detected}, extension suggests {expected}", expected)
