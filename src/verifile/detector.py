import magic

def detect_file_type(filepath, as_mime=False):
    try:
        file_type = magic.from_file(filepath, mime=as_mime)
        return file_type
    except Exception as e:
        print(f"Error detecting file type: {e}")
        return None