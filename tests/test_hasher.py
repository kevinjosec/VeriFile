import pytest

from verifile.hasher import ChecksumFormatError, hash_file, parse_checksum_file, parse_expected

ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
ABC_MD5 = "900150983cd24fb0d6963f7d28e17f72"


def test_hash_file_multiple_algorithms(make_file):
    path = make_file("abc.txt", b"abc")
    result = hash_file(path, ["sha256", "md5"])
    assert result == {"sha256": ABC_SHA256, "md5": ABC_MD5}


def test_hash_large_file_spanning_chunks(make_file):
    import hashlib

    data = b"x" * (3 * 1024 * 1024 + 7)
    path = make_file("big.bin", data)
    assert hash_file(path)["sha256"] == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (ABC_SHA256.upper(), ("sha256", ABC_SHA256)),
        (f"sha256:{ABC_SHA256}", ("sha256", ABC_SHA256)),
        (f"SHA-256:{ABC_SHA256}", ("sha256", ABC_SHA256)),
        (ABC_MD5, ("md5", ABC_MD5)),
    ],
)
def test_parse_expected(value, expected):
    assert parse_expected(value) == expected


@pytest.mark.parametrize("bad", ["xyz", "abc123", f"md5:{ABC_SHA256}", f"crc32:{ABC_MD5}", ""])
def test_parse_expected_rejects_bad_input(bad):
    with pytest.raises(ChecksumFormatError):
        parse_expected(bad)


def test_parse_checksum_file_gnu_and_bsd(tmp_path):
    sums = tmp_path / "SUMS"
    sums.write_text(
        f"# comment\n{ABC_SHA256}  a.txt\n{ABC_MD5} *b.bin\nSHA256 (c d.txt) = {ABC_SHA256}\n",
        encoding="utf-8",
    )
    entries = list(parse_checksum_file(str(sums)))
    assert [(e[1], e[0].endswith(n)) for e, n in zip(entries, ["a.txt", "b.bin", "c d.txt"])] == [
        ("sha256", True), ("md5", True), ("sha256", True),
    ]


def test_parse_checksum_file_rejects_garbage(tmp_path):
    sums = tmp_path / "SUMS"
    sums.write_text("this is not a checksum line\n", encoding="utf-8")
    with pytest.raises(ChecksumFormatError):
        list(parse_checksum_file(str(sums)))
