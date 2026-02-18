def print_report(filename: str, filesize: int, extension: str, filetype: str, filehash: str, mismatch: bool) -> None:
    print("\n" + "=" * 50)
    print("VeriFile Analysis Report")
    print("=" * 50)
    print(f"File name:{filename} ")
    print(f"File size: {filesize}")
    print(f"Extension: {extension}")
    print(f"Type: {filetype}")
    print(f"Hash: {filehash}")
    
    if mismatch:
        print(f"Signature: ❌ Mismatch Detected")
    else:
        print(f"Signature: ✅ No Mismatch Detected")
    print("=" * 50 + "\n")
    
    