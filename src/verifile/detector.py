import magic

def detect_file_type(filepath, as_mime=False):
    try:
        file_type = magic.from_file(filepath, mime=as_mime)
        return file_type if file_type else None
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except PermissionError:
        raise PermissionError(f"Permission denied reading: {filepath}")
    except Exception as e:
        raise RuntimeError(f"Failed to detect file type: {e}")