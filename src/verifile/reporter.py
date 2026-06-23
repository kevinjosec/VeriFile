import sys

def print_report(filename: str, filesize: int, extension: str, filetype: str, filehash: str, mismatch: bool) -> None:
    print("\n" + "=" * 50)
    print("VeriFile Analysis Report")
    print("=" * 50)
    print(f"File name: {filename}")
    print(f"File size: {filesize} bytes")
    print(f"Extension: {extension}")
    print(f"Type: {filetype}")
    print(f"Hash: {filehash}")

    if mismatch:
        status = "❌ Mismatch Detected" if sys.stdout.encoding == 'utf-8' else "[!] Mismatch Detected"
        print(f"Signature: {status} (extension/MIME type mismatch)")
    else:
        status = "✅ No Mismatch Detected" if sys.stdout.encoding == 'utf-8' else "[OK] No Mismatch Detected"
        print(f"Signature: {status}")
    print("=" * 50 + "\n")
    
    