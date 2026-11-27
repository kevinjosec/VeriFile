"""Knowledge about file types: extension -> MIME, MIME aliases and families.

The extension table is built in so results are identical on every OS.
(``mimetypes.init()`` reads the Windows registry, which makes it vary by machine.)
"""

from __future__ import annotations

import mimetypes
import os
from typing import Optional

# Extension (lowercase, no dot) -> canonical MIME type.
EXTENSION_MIME: dict[str, str] = {
    # Images
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "jpe": "image/jpeg", "jfif": "image/jpeg",
    "png": "image/png", "gif": "image/gif", "bmp": "image/bmp", "webp": "image/webp",
    "tif": "image/tiff", "tiff": "image/tiff", "ico": "image/vnd.microsoft.icon",
    "svg": "image/svg+xml", "heic": "image/heic", "heif": "image/heif", "avif": "image/avif",
    "psd": "image/vnd.adobe.photoshop",
    # Audio / video
    "mp3": "audio/mpeg", "wav": "audio/wav", "flac": "audio/flac", "ogg": "audio/ogg",
    "oga": "audio/ogg", "m4a": "audio/mp4", "aac": "audio/aac", "opus": "audio/ogg",
    "mp4": "video/mp4", "m4v": "video/mp4", "mov": "video/quicktime", "avi": "video/x-msvideo",
    "mkv": "video/x-matroska", "webm": "video/webm", "wmv": "video/x-ms-wmv",
    "flv": "video/x-flv", "ogv": "video/ogg",
    # Documents
    "pdf": "application/pdf", "rtf": "text/rtf", "txt": "text/plain", "md": "text/markdown",
    "csv": "text/csv", "tsv": "text/tab-separated-values", "html": "text/html",
    "htm": "text/html", "xml": "application/xml", "json": "application/json",
    "yaml": "application/yaml", "yml": "application/yaml", "toml": "application/toml",
    "ini": "text/plain", "cfg": "text/plain", "log": "text/plain", "css": "text/css",
    "doc": "application/msword", "xls": "application/vnd.ms-excel",
    "ppt": "application/vnd.ms-powerpoint", "msg": "application/vnd.ms-outlook",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "odt": "application/vnd.oasis.opendocument.text",
    "ods": "application/vnd.oasis.opendocument.spreadsheet",
    "odp": "application/vnd.oasis.opendocument.presentation",
    "epub": "application/epub+zip",
    # Source code / scripts
    "py": "text/x-python", "js": "text/javascript", "mjs": "text/javascript",
    "ts": "text/plain", "sh": "text/x-shellscript", "bash": "text/x-shellscript",
    "bat": "text/x-msdos-batch", "cmd": "text/x-msdos-batch", "ps1": "text/plain",
    "c": "text/x-c", "h": "text/x-c", "cpp": "text/x-c++", "java": "text/x-java",
    "go": "text/plain", "rs": "text/plain", "rb": "text/x-ruby", "php": "text/x-php",
    "pl": "text/x-perl", "sql": "application/sql",
    # Archives
    "zip": "application/zip", "gz": "application/gzip", "tgz": "application/gzip",
    "bz2": "application/x-bzip2", "xz": "application/x-xz", "7z": "application/x-7z-compressed",
    "rar": "application/vnd.rar", "tar": "application/x-tar", "zst": "application/zstd",
    "jar": "application/java-archive", "apk": "application/vnd.android.package-archive",
    "whl": "application/zip", "iso": "application/x-iso9660-image",
    # Executables / binaries
    "exe": "application/vnd.microsoft.portable-executable",
    "dll": "application/vnd.microsoft.portable-executable",
    "sys": "application/vnd.microsoft.portable-executable",
    "scr": "application/vnd.microsoft.portable-executable",
    "cpl": "application/vnd.microsoft.portable-executable",
    "ocx": "application/vnd.microsoft.portable-executable",
    "msi": "application/x-msi", "so": "application/x-executable",
    "elf": "application/x-executable", "dylib": "application/x-mach-binary",
    "class": "application/java-vm", "pyc": "application/x-python-code",
    "wasm": "application/wasm", "sqlite": "application/vnd.sqlite3",
    "db": "application/vnd.sqlite3",
}

# Variant spellings -> canonical MIME (keys are lowercase).
MIME_ALIASES: dict[str, str] = {
    "image/jpg": "image/jpeg", "image/pjpeg": "image/jpeg",
    "image/x-png": "image/png",
    "image/x-ms-bmp": "image/bmp", "image/x-bmp": "image/bmp",
    "image/x-icon": "image/vnd.microsoft.icon",
    "application/x-zip-compressed": "application/zip", "application/x-zip": "application/zip",
    "text/xml": "application/xml",
    "application/javascript": "text/javascript", "application/x-javascript": "text/javascript",
    "text/x-script.python": "text/x-python", "application/x-python": "text/x-python",
    "text/x-sh": "text/x-shellscript", "application/x-sh": "text/x-shellscript",
    "application/x-shellscript": "text/x-shellscript",
    "application/x-pdf": "application/pdf",
    "audio/x-wav": "audio/wav", "audio/wave": "audio/wav", "audio/vnd.wave": "audio/wav",
    "audio/mp3": "audio/mpeg", "audio/x-mp3": "audio/mpeg", "audio/mpeg3": "audio/mpeg",
    "audio/x-flac": "audio/flac", "audio/x-m4a": "audio/mp4",
    "application/x-gzip": "application/gzip",
    "application/x-bzip": "application/x-bzip2",
    "application/x-rar": "application/vnd.rar",
    "application/x-rar-compressed": "application/vnd.rar",
    "application/x-yaml": "application/yaml", "text/yaml": "application/yaml",
    "text/x-yaml": "application/yaml",
    "application/x-msdownload": "application/vnd.microsoft.portable-executable",
    "application/x-dosexec": "application/vnd.microsoft.portable-executable",
    "application/x-ms-dos-executable": "application/vnd.microsoft.portable-executable",
    "application/x-msdos-program": "application/vnd.microsoft.portable-executable",
    "application/x-elf": "application/x-executable",
    "application/x-pie-executable": "application/x-executable",
    "application/x-sharedlib": "application/x-executable",
    "application/x-mach-o-executable": "application/x-mach-binary",
    "application/x-sqlite3": "application/vnd.sqlite3",
    "application/x-iso9660": "application/x-iso9660-image",
    "application/x-bat": "text/x-msdos-batch",
    "text/x-c++src": "text/x-c++", "text/x-csrc": "text/x-c",
}

# Extensions whose files are really ZIP archives underneath.
ZIP_CONTAINER_EXTS = frozenset({
    "zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "odt", "ods", "odp", "epub",
    "jar", "war", "ear", "apk", "aab", "ipa", "xpi", "vsix", "whl", "nupkg", "kmz", "3mf",
    "xps", "oxps", "cbz", "sketch",
})

# Legacy Office / OLE compound-file formats (libmagic often only reports the container).
OLE_MIMES = frozenset({
    "application/x-ole-storage", "application/cdfv2", "application/vnd.ms-office",
    "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
    "application/vnd.ms-outlook", "application/x-msi",
})

# Detected types that can execute code if run.
EXECUTABLE_MIMES = frozenset({
    "application/vnd.microsoft.portable-executable", "application/x-executable",
    "application/x-mach-binary", "application/x-msi", "application/java-vm",
    "text/x-shellscript", "text/x-msdos-batch",
})

# Extensions where executable content is expected.
EXECUTABLE_EXTS = frozenset({
    "exe", "dll", "sys", "scr", "com", "cpl", "ocx", "msi", "so", "elf", "bin", "out",
    "dylib", "app", "class", "sh", "bash", "zsh", "bat", "cmd", "run", "appimage", "o", "ko",
})

_TEXTUAL_APPLICATION = frozenset({
    "application/json", "application/xml", "application/yaml", "application/toml",
    "application/sql", "application/x-ndjson", "application/x-httpd-php",
})

_fallback_mimetypes = mimetypes.MimeTypes()  # built-in table only, no registry lookup


def normalize_mime(mime: Optional[str]) -> Optional[str]:
    """Lowercase, drop parameters (``; charset=...``) and resolve aliases."""
    if not mime:
        return None
    mime = mime.split(";", 1)[0].strip().lower()
    if not mime:
        return None
    return MIME_ALIASES.get(mime, mime)


def extension_of(path: str) -> str:
    """Lowercase extension without the dot, or ``""`` if there is none."""
    name = os.path.basename(path)
    if name.startswith(".") and name.count(".") == 1:  # dotfiles like ".bashrc"
        return ""
    return os.path.splitext(name)[1].lstrip(".").lower()


def expected_mime_for(path: str) -> Optional[str]:
    """MIME type implied by the file's extension, or None if unknown."""
    ext = extension_of(path)
    if not ext:
        return None
    if ext in EXTENSION_MIME:
        return EXTENSION_MIME[ext]
    guessed, _ = _fallback_mimetypes.guess_type("x." + ext, strict=False)
    return normalize_mime(guessed)


def is_textual(mime: Optional[str]) -> bool:
    if not mime:
        return False
    return (
        mime.startswith("text/")
        or mime in _TEXTUAL_APPLICATION
        or mime.endswith("+json")
        or mime.endswith("+xml")
    )


def is_executable(mime: Optional[str]) -> bool:
    return bool(mime) and mime in EXECUTABLE_MIMES
