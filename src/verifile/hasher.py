import hashlib

def calculate_hash256(filepath: str) -> str:
    hasher_object = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                hasher_object.update(chunk)
        return hasher_object.hexdigest()
    except Exception as e :
        raise RuntimeError(f"Failed to calculate the hash: {e}")
    