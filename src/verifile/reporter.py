"""Render scan results as human-readable text or JSON."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from typing import Optional, TextIO

from verifile import __version__
from verifile.analysis import COMPATIBLE, EMPTY, HIGH, LOW, MATCH, MEDIUM, MISMATCH
from verifile.scanner import FileReport

_FANCY = {"ok": "✅", "warn": "⚠️ ", "bad": "❌", "info": "ℹ️ "}
_PLAIN = {"ok": "[OK]", "warn": "[!]", "bad": "[X]", "info": "[i]"}


def _symbols(stream: TextIO) -> dict[str, str]:
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "".join(_FANCY.values()).encode(encoding)
        return _FANCY
    except (UnicodeEncodeError, LookupError):
        return _PLAIN


def human_size(size: Optional[int]) -> str:
    if size is None:
        return "?"
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{size} bytes" if unit == "B" else f"{value:.1f} {unit} ({size:,} bytes)"
        value /= 1024
    return f"{size} bytes"  # pragma: no cover


def _verdict_line(report: FileReport, sym: dict[str, str]) -> str:
    v = report.verdict
    if v is None:
        return ""
    if v.status == MATCH:
        return f"{sym['ok']} Match ({v.reason})"
    if v.status == COMPATIBLE:
        return f"{sym['ok']} Compatible ({v.reason})"
    if v.status == EMPTY:
        return f"{sym['info']} Empty file"
    if v.status == MISMATCH:
        icon = sym["bad"] if v.severity in (HIGH, MEDIUM) else sym["warn"]
        return f"{icon} MISMATCH [{v.severity.upper()} risk] ({v.reason})"
    icon = sym["warn"] if v.severity == LOW else sym["info"]
    return f"{icon} Unknown ({v.reason})"


def print_text(reports: Sequence[FileReport], stream: Optional[TextIO] = None,
               err: Optional[TextIO] = None, quiet: bool = False) -> None:
    stream = stream or sys.stdout
    err = err or sys.stderr
    sym = _symbols(stream)
    printed_block = False
    for report in reports:
        if report.error:
            print(f"verifile: {report.path}: {report.error}", file=err)
            continue
        if quiet:
            if report.has_problem:
                parts = []
                if report.verdict and report.verdict.is_problem:
                    parts.append(f"type mismatch [{report.verdict.severity}]: "
                                 f"{report.verdict.reason}")
                if report.hash_check and not report.hash_check.ok:
                    parts.append(f"{report.hash_check.algorithm} checksum FAILED")
                print(f"{report.path}: {'; '.join(parts)}", file=stream)
            continue

        d = report.detection
        rows = [
            ("File", report.path),
            ("Size", human_size(report.size)),
            ("Extension", f".{report.extension}" if report.extension else "(none)"),
            ("Detected", f"{d.mime}" + (f" - {d.description}" if d and d.description else "")
             if d else "?"),
        ]
        if report.verdict and report.verdict.expected_mime:
            rows.append(("Expected", report.verdict.expected_mime))
        rows.append(("Signature", _verdict_line(report, sym)))
        for algo, digest in report.hashes.items():
            rows.append((algo.upper(), digest))
        if report.hash_check:
            hc = report.hash_check
            rows.append(("Checksum", f"{sym['ok']} {hc.algorithm} verified" if hc.ok
                         else f"{sym['bad']} {hc.algorithm} MISMATCH (expected {hc.expected})"))

        printed_block = True
        width = max(len(k) for k, _ in rows)
        print("=" * 60, file=stream)
        for key, value in rows:
            print(f"{key:<{width}} : {value}", file=stream)
    if printed_block:
        print("=" * 60, file=stream)
    if len(reports) > 1 and not quiet:
        print(summary_line(reports), file=stream)


def summary_line(reports: Sequence[FileReport]) -> str:
    s = summarize(reports)
    return (f"Scanned {s['files']} file(s): {s['mismatches']} type mismatch(es), "
            f"{s['checksum_failures']} checksum failure(s), {s['errors']} error(s)")


def summarize(reports: Sequence[FileReport]) -> dict:
    return {
        "files": len(reports),
        "mismatches": sum(1 for r in reports if r.verdict and r.verdict.status == MISMATCH),
        "high_risk": sum(1 for r in reports
                         if r.verdict and r.verdict.status == MISMATCH
                         and r.verdict.severity == HIGH),
        "checksum_failures": sum(1 for r in reports if r.hash_check and not r.hash_check.ok),
        "errors": sum(1 for r in reports if r.error),
    }


def print_json(reports: Sequence[FileReport], stream: Optional[TextIO] = None) -> None:
    stream = stream or sys.stdout
    doc = {
        "tool": "verifile",
        "version": __version__,
        "summary": summarize(reports),
        "files": [r.to_dict() for r in reports],
    }
    json.dump(doc, stream, indent=2, ensure_ascii=False)
    stream.write("\n")
