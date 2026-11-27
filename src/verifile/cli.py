"""Command-line interface.

Exit codes:
    0  every file checked out
    1  a type mismatch or checksum failure was found
    2  usage error, or a file could not be read
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from verifile import __version__
from verifile.detector import BACKENDS, DetectionError, resolve_backend
from verifile.hasher import ALGORITHMS, ChecksumFormatError, parse_checksum_file, parse_expected
from verifile.reporter import print_json, print_text
from verifile.scanner import analyze_file, iter_files

EXIT_OK, EXIT_PROBLEM, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verifile",
        description="VeriFile - identify a file's real type and verify its integrity.",
        epilog="Exit codes: 0 = clean, 1 = mismatch or checksum failure, 2 = error.",
    )
    parser.add_argument("paths", nargs="*", metavar="PATH", help="files (or directories with -r)")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="scan directories recursively")
    parser.add_argument("-a", "--algorithm", dest="algorithms", action="append",
                        choices=ALGORITHMS, metavar="ALGO",
                        help=f"hash algorithm, repeatable ({', '.join(ALGORITHMS)}; "
                             "default sha256)")
    parser.add_argument("-e", "--expected", metavar="[ALGO:]HASH",
                        help="expected hash of a single file; algorithm inferred from length")
    parser.add_argument("-c", "--checksums", metavar="FILE",
                        help="verify every file listed in a sha256sum/md5sum/BSD-style file")
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only print files with problems")
    parser.add_argument("--backend", choices=BACKENDS, default="auto",
                        help="type detection engine (default: auto)")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    algorithms = args.algorithms or ["sha256"]

    if not args.paths and not args.checksums:
        parser.error("give at least one PATH or --checksums FILE")
    if args.expected and (args.checksums or len(args.paths) != 1 or args.recursive):
        parser.error("--expected works with exactly one file")

    try:
        backend = resolve_backend(args.backend)
    except DetectionError as e:
        print(f"verifile: {e}", file=sys.stderr)
        return EXIT_ERROR

    jobs: list[tuple[str, Optional[tuple[str, str]]]] = []
    try:
        if args.expected:
            jobs.append((args.paths[0], parse_expected(args.expected)))
        else:
            jobs.extend((p, None) for p in iter_files(args.paths, args.recursive))
        if args.checksums:
            jobs.extend((p, (algo, digest))
                        for p, algo, digest in parse_checksum_file(args.checksums))
    except ChecksumFormatError as e:
        parser.error(str(e))
    except OSError as e:
        print(f"verifile: {args.checksums}: {e.strerror or e}", file=sys.stderr)
        return EXIT_ERROR

    reports = [analyze_file(path, algorithms, expected, backend) for path, expected in jobs]

    if args.json:
        print_json(reports)
    else:
        print_text(reports, quiet=args.quiet)

    if any(r.error for r in reports):
        return EXIT_ERROR
    if any(r.has_problem for r in reports):
        return EXIT_PROBLEM
    return EXIT_OK


def run() -> None:
    """Console-script entry point."""
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("verifile: interrupted", file=sys.stderr)
        sys.exit(130)
