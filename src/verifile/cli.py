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
    
    if not os.path.isfile(filepath):
        print(f"Error: Path is not a file.")
        sys.exit(1)
        
    detected_mime = detect_file_type(filepath, as_mime=True)
    guessed_mime, _ = mimetypes.guess_type(filepath)
    
    mismatch = False
    
    if guessed_mime and detected_mime:
        mismatch = guessed_mime != detected_mime
        
    hashed_file = calculate_hash256(filepath)
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    print_report(
    filename=filename,
    filesize=filesize,
    extension=guessed_mime.split("/")[-1] if guessed_mime else None,
    filetype=detected_mime,
    filehash=hashed_file,
    mismatch=mismatch
)
