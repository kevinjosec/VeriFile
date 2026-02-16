import argparse
import sys
import os

from verifile.hasher import calculate_hash256
from verifile.detector import detect_file_type
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
        
    detector_result = detect_file_type(filepath, as_mime=True)    
    extension = os.path.splitext(filepath)[1].lower()
    
    mismatch = False
    if extension:
        ext_clean = extension.replace(".", "")
    if "/" in detector_result:
        mime_subtype = detector_result.split("/")[-1].lower()
        if ext_clean != mime_subtype:
            mismatch = True
    
    hashed_file = calculate_hash256(filepath)
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    print_report(
    filename=filename,
    filesize=filesize,
    extension=extension,
    filetype=detector_result,
    filehash=hashed_file,
    mismatch=mismatch
)


if __name__ == "__main__":
    main()
