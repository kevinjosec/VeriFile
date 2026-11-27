import pytest

PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 64
PE = b"MZ" + b"\x90\x00" * 30 + b"\x00" * 200
ZIP = b"PK\x03\x04" + b"\x14\x00" + b"\x00" * 100
PDF = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\n" + b"\x00" * 32


@pytest.fixture
def make_file(tmp_path):
    def _make(name: str, content: bytes) -> str:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return str(path)

    return _make
