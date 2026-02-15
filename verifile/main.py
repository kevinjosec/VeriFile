import argparse
import sys
import os

from verifile.detector import detect_file_type

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
    
    if not os.path.exists(filepath):
        print(f"Error: File does not exist.")
        sys.exit(1)
    
    if not os.path.isfile(filepath):
        print(f"Error: Path is not a file.")
        sys.exit(1)
        
    detector_result = detect_file_type(filepath, as_mime=True)
    print(f"Detected file type: {detector_result}")
    
    extention = os.path.splitext(filepath)
    extention = extention[1].lower()
    print(f"File extension: {extention}")

if __name__ == "__main__":
    main()
