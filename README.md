# VeriFile

VeriFile is a command-line file identification and integrity analysis tool built in Python.

It detects the true file type using magic number analysis and verifies file integrity using cryptographic hashing.

## Features

- File type detection using libmagic
- SHA256 hash generation
- Extension mismatch detection
- Clean CLI interface

## Usage

python -m verifile.main <file_path>

## Roadmap

- Directory scanning
- JSON output
- Entropy analysis
- Malware heuristics
