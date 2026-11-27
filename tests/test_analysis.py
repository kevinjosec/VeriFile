import pytest

from verifile.analysis import COMPATIBLE, EMPTY, HIGH, MATCH, MISMATCH, UNKNOWN, evaluate
from verifile.filetypes import expected_mime_for, extension_of, normalize_mime


@pytest.mark.parametrize(
    ("path", "detected", "status"),
    [
        ("photo.png", "image/png", MATCH),
        ("photo.jpg", "image/jpg", MATCH),                      # alias
        ("script.py", "text/x-script.python", MATCH),           # libmagic spelling
        ("data.csv", "text/plain", COMPATIBLE),                 # text can't be told apart
        ("data.json", "text/plain", COMPATIBLE),
        ("report.docx", "application/zip", COMPATIBLE),         # ZIP container
        ("old.doc", "application/cdfv2", COMPATIBLE),           # OLE container
        ("Makefile", "text/plain", UNKNOWN),                    # no extension != mismatch
        ("LICENSE", "text/plain", UNKNOWN),
        (".bashrc", "text/plain", UNKNOWN),
        ("blob.weird", "image/png", UNKNOWN),                   # unknown extension
        ("empty.txt", "inode/x-empty", EMPTY),
        ("notes.txt", "image/png", MISMATCH),
        ("photo.png", "application/pdf", MISMATCH),
        ("setup.exe", "application/x-dosexec", MATCH),
    ],
)
def test_verdict_status(path, detected, status):
    assert evaluate(path, detected).status == status


def test_disguised_executable_is_high_risk():
    v = evaluate("invoice.pdf", "application/x-dosexec")
    assert v.status == MISMATCH
    assert v.severity == HIGH


def test_disguised_script_is_high_risk():
    assert evaluate("cat.jpg", "text/x-shellscript").severity == HIGH


def test_normalize_mime_strips_params_and_case():
    assert normalize_mime("Text/XML; charset=utf-8") == "application/xml"
    assert normalize_mime("") is None
    assert normalize_mime(None) is None


def test_extension_helpers():
    assert extension_of("a/b/Photo.JPG") == "jpg"
    assert extension_of(".gitignore") == ""
    assert extension_of("archive.tar.gz") == "gz"
    assert expected_mime_for("x.png") == "image/png"
    assert expected_mime_for("noext") is None
