# VeriFile

VeriFile is a command-line tool that tells you **what a file really is** and **whether it is
the file you expect**.

- **True type detection.** Identifies files by their content (magic numbers), not by their name.
- **Disguised-file detection.** Flags files whose extension lies about their content, and rates
  the risk. An executable renamed to `invoice.pdf` is a **HIGH** risk.
- **Integrity verification.** Hashes with MD5, SHA-1, SHA-256 or SHA-512, checks a file against
  an expected hash, or verifies a whole `SHA256SUMS` file.
- **Built for scripts.** Meaningful exit codes, `--json` output, quiet mode, recursive scans.
- **Works everywhere.** Pure-Python detection out of the box on Windows, macOS and Linux;
  uses libmagic automatically when it is installed.

## Installation

```bash
pip install verifile
```

Optional, for more accurate detection with libmagic:

```bash
pip install "verifile[libmagic]"
# plus the native library:
sudo apt install libmagic1        # Debian/Ubuntu
brew install libmagic             # macOS
pip install python-magic-bin      # Windows (bundles the DLL; use instead of [libmagic])
```

## Usage

```bash
verifile photo.png                          # identify + SHA-256
verifile -r ./downloads                     # scan a directory tree
verifile -q -r ./downloads                  # only show problems
verifile -a md5 -a sha512 file.iso          # choose hash algorithms
verifile --expected 3a7bd3e2...  file.iso   # verify against a published hash
verifile --expected sha1:da39a3ee... file   # explicit algorithm
verifile --checksums SHA256SUMS             # verify every file listed
verifile --json -r . > report.json          # machine-readable output
```

Example:

```text
$ verifile holiday.jpg
============================================================
File      : holiday.jpg
Size      : 103.7 KiB (106,208 bytes)
Extension : .jpg
Detected  : application/vnd.microsoft.portable-executable - PE32+ executable (console) x86-64
Expected  : image/jpeg
Signature : ❌ MISMATCH [HIGH risk] (executable content disguised as .jpg)
SHA256    : 9f29...
============================================================
```

### What the signature verdicts mean

| Verdict      | Meaning                                                                       |
|--------------|-------------------------------------------------------------------------------|
| `match`      | Content matches the extension.                                                |
| `compatible` | Different label, same family. For example, `.docx` is a ZIP and `.csv` is plain text. |
| `mismatch`   | The extension lies about the content. Risk is `low`, `medium` or `high` (executable). |
| `unknown`    | Nothing to compare: the file has no extension, or the type is unrecognised.   |
| `empty`      | Zero-byte file.                                                               |

### Exit codes

| Code | Meaning                                         |
|------|-------------------------------------------------|
| 0    | Everything checked out                          |
| 1    | A type mismatch or checksum failure was found   |
| 2    | Usage error, or a file could not be read        |

### Detection backends

`--backend auto` (the default) uses libmagic when it is available and the bundled pure-Python
detector otherwise. Force one with `--backend libmagic` or `--backend puremagic`.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
```

## License

MIT
