import json

import pytest
from conftest import PE, PNG

from verifile import __version__
from verifile.cli import EXIT_ERROR, EXIT_OK, EXIT_PROBLEM, main

ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def run(*args):
    return main(["--backend", "puremagic", *args])


def test_clean_file_exits_zero(make_file, capsys):
    path = make_file("photo.png", PNG)
    assert run(path) == EXIT_OK
    out = capsys.readouterr().out
    assert "image/png" in out
    assert "SHA256" in out


def test_disguised_exe_exits_one(make_file, capsys):
    assert run(make_file("invoice.pdf", PE)) == EXIT_PROBLEM
    assert "HIGH" in capsys.readouterr().out


def test_no_extension_is_not_a_mismatch(make_file):
    assert run(make_file("Makefile", b"all:\n\techo hi\n")) == EXIT_OK


def test_missing_file_goes_to_stderr_and_exits_two(tmp_path, capsys):
    assert run(str(tmp_path / "nope.txt")) == EXIT_ERROR
    captured = capsys.readouterr()
    assert "nope.txt" in captured.err
    assert captured.out == ""


def test_directory_without_recursive_is_error(tmp_path, capsys):
    assert run(str(tmp_path)) == EXIT_ERROR
    assert "-r" in capsys.readouterr().err


def test_recursive_scan_and_summary(make_file, tmp_path, capsys):
    make_file("a/ok.png", PNG)
    make_file("a/b/bad.txt", PE)
    assert run("-r", str(tmp_path)) == EXIT_PROBLEM
    assert "Scanned 2 file(s): 1 type mismatch(es)" in capsys.readouterr().out


def test_json_output(make_file, capsys):
    path = make_file("photo.png", PNG)
    assert run("--json", "-a", "md5", "-a", "sha256", path) == EXIT_OK
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == __version__
    entry = doc["files"][0]
    assert entry["detection"]["mime"] == "image/png"
    assert entry["verdict"]["status"] == "match"
    assert set(entry["hashes"]) == {"md5", "sha256"}


def test_expected_hash_ok_and_fail(make_file, capsys):
    path = make_file("abc.txt", b"abc")
    assert run("--expected", ABC_SHA256, path) == EXIT_OK
    assert run("--expected", "0" * 64, path) == EXIT_PROBLEM
    assert "MISMATCH" in capsys.readouterr().out


def test_expected_requires_single_file(make_file):
    with pytest.raises(SystemExit) as exc:
        run("--expected", ABC_SHA256, make_file("a.txt", b"a"), make_file("b.txt", b"b"))
    assert exc.value.code == 2


def test_checksums_file(make_file, tmp_path, capsys):
    make_file("abc.txt", b"abc")
    make_file("other.txt", b"other")
    sums = make_file("SHA256SUMS", f"{ABC_SHA256}  abc.txt\n{'0' * 64}  other.txt\n".encode())
    assert run("-q", "--checksums", sums) == EXIT_PROBLEM
    out = capsys.readouterr().out
    assert "other.txt" in out and "abc.txt" not in out


def test_quiet_prints_nothing_when_clean(make_file, capsys):
    assert run("-q", make_file("photo.png", PNG)) == EXIT_OK
    assert capsys.readouterr().out == ""


def test_no_arguments_is_usage_error():
    with pytest.raises(SystemExit) as exc:
        run()
    assert exc.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit):
        run("--version")
    assert __version__ in capsys.readouterr().out
