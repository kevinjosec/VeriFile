"""Analyse files and produce structured reports (no printing here)."""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Optional

from verifile.analysis import Verdict, evaluate
from verifile.detector import Detection, DetectionError, detect_file_type
from verifile.filetypes import extension_of
from verifile.hasher import DEFAULT_ALGORITHMS, digests_equal, hash_file


@dataclass
class HashCheck:
    algorithm: str
    expected: str
    actual: Optional[str]
    ok: bool

    def to_dict(self) -> dict:
        return {"algorithm": self.algorithm, "expected": self.expected,
                "actual": self.actual, "ok": self.ok}


@dataclass
class FileReport:
    path: str
    size: Optional[int] = None
    extension: str = ""
    detection: Optional[Detection] = None
    verdict: Optional[Verdict] = None
    hashes: dict[str, str] = field(default_factory=dict)
    hash_check: Optional[HashCheck] = None
    error: Optional[str] = None

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def has_problem(self) -> bool:
        return bool(
            (self.verdict and self.verdict.is_problem)
            or (self.hash_check and not self.hash_check.ok)
        )

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "size": self.size,
            "extension": self.extension or None,
            "detection": self.detection.to_dict() if self.detection else None,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "hashes": self.hashes,
            "hash_check": self.hash_check.to_dict() if self.hash_check else None,
            "error": self.error,
        }


def analyze_file(
    path: str,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    expected: Optional[tuple[str, str]] = None,
    backend: str = "auto",
) -> FileReport:
    """Analyse one file. Never raises for per-file problems; they go in ``report.error``."""
    report = FileReport(path=path, extension=extension_of(path))
    algorithms = list(dict.fromkeys(algorithms))
    if expected and expected[0] not in algorithms:
        algorithms.append(expected[0])

    try:
        if not os.path.exists(path):
            raise FileNotFoundError("no such file")
        if os.path.isdir(path):
            raise IsADirectoryError("is a directory (use -r to scan directories)")
        if not os.path.isfile(path):
            raise OSError("not a regular file")
        report.size = os.path.getsize(path)
        report.detection = detect_file_type(path, backend=backend)
        report.verdict = evaluate(path, report.detection.mime)
        report.hashes = hash_file(path, algorithms)
    except PermissionError:
        report.error = "permission denied"
        return report
    except (OSError, DetectionError) as e:
        report.error = getattr(e, "strerror", None) or str(e) or type(e).__name__
        return report

    if expected:
        algo, digest = expected
        actual = report.hashes.get(algo)
        report.hash_check = HashCheck(algo, digest, actual,
                                      actual is not None and digests_equal(actual, digest))
    return report


def iter_files(paths: Iterable[str], recursive: bool) -> Iterator[str]:
    """Expand directories (when ``recursive``) into the files they contain, sorted."""
    for path in paths:
        if recursive and os.path.isdir(path):
            for root, dirs, files in os.walk(path):  # does not follow directory symlinks
                dirs.sort()
                for name in sorted(files):
                    yield os.path.normpath(os.path.join(root, name))
        else:
            yield path
