import argparse
import os
import sys
import mimetypes

from verifile.detector import detect_file_type
from verifile.hasher import calculate_hash256
from verifile.reporter import print_report

def main():
    parser = argparse.ArgumentParser(
        description="VerifIle - File Identification and Verification Tool"
    )

    parser.add_argument(
        "filepath",
        help="Path to the file to be identified and verified"
    )

    args=parser.parse_args()
    filepath = args.filepath
    print(f"Identifying and verifying file {filepath}...")

    if not os.path.isfile(filepath):
        print("Error: Invalid file path.")
        sys.exit(1)

    try:
        detected_mime = detect_file_type(filepath, as_mime=True)
    except (FileNotFoundError, PermissionError, RuntimeError) as e:
        print(f"Error: {e}")
        sys.exit(1)

    guessed_mime, _ = mimetypes.guess_type(filepath)

    mismatch = False
    if guessed_mime and detected_mime:
        mismatch = guessed_mime != detected_mime
    elif guessed_mime is None and detected_mime:
        mismatch = True

    try:
        hashed_file = calculate_hash256(filepath)
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    file_extension = os.path.splitext(filename)[1].lstrip('.').lower() or "unknown"

    print_report(
        filename=filename,
        filesize=filesize,
        extension=file_extension,
        filetype=detected_mime,
        filehash=hashed_file,
        mismatch=mismatch
    )
