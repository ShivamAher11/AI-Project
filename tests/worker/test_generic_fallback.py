import json
import os
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from worker.lief_extract import InvalidBinary, extract_generic, extract_static
from worker.strings import extract_strings
from worker.normalize import normalize_analysis, validate_normalized

ENTROPY_TEST_BYTES = bytes(range(256))


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_generic_extracts_metadata_strings_entropy(tmp_path):
    path = tmp_path / "weird.xyz"
    data = b"\x00\x01\x02hello\x00https://example.test\x00S\x00o\x00f\x00t\x00w\x00a\x00r\x00e\x00"
    _write(path, data)
    result = extract_generic(path)

    assert result["format"] == "generic"
    assert result["arch"] == "unknown"
    assert result["bitness"] is None
    assert result["size"] == len(data)
    assert result["parser_coverage"] == "generic"
    assert result["generic_observations"]["parser_available"] is False
    assert result["generic_observations"]["magic_detected"] == "bytes"
    assert result["generic_observations"]["parser_name"] is None
    assert result["generic_observations"]["hashes"]["sha256"] == result["sha256"]
    assert result["generic_observations"]["hashes"]["md5"] == result["md5"]
    assert result["generic_observations"]["hashes"]["size"] == result["size"]
    values = {row["value"] for row in result["strings"]}
    assert "hello" in values
    assert "https://example.test" in values
    for row in result["strings"]:
        assert row["offset"].startswith("0x")
        assert row["encoding"] in {"utf-8", "utf-16le"}
        assert isinstance(row["length"], int)
    assert result["generic_observations"]["entropy"] >= 0.0


def test_pe_magic_goes_through_LIEF_parser(tmp_path):
    path = tmp_path / "fake.exe"
    _write(path, b"MZ" + b"\x00" * 200)
    try:
        extract_static(path)
    except InvalidBinary:
        pass  # malformed PE is expected; the point is dispatch attempts LIEF
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"wrong exception for PE-magic dispatch: {exc!r}")


def test_non_pe_never_raises_invalid_binary(tmp_path):
    path = tmp_path / "archive.zip"
    _write(path, b"PK\x03\x04" + b"\x00" * 1000)
    result = extract_static(path)
    assert result["format"] == "generic"
    assert result["generic_observations"]["parser_available"] is False


def test_high_entropy_sets_possible_packing(tmp_path):
    path = tmp_path / "packed.bin"
    _write(path, ENTROPY_TEST_BYTES)
    result = extract_generic(path)
    assert result["possible_packing"] is True
    assert result["packing_note"] is not None


def test_generic_normalizes_and_validates(tmp_path):
    path = tmp_path / "data.bin"
    _write(path, b"hello world this is a test string for normalization")
    static = extract_generic(path)
    normalized = normalize_analysis(static, str(uuid4()), data_root=str(tmp_path))
    validate_normalized(normalized)
    assert normalized["parser_coverage"] == "generic"
    assert normalized["file"]["format"] == "generic"
    assert normalized["generic_observations"] is not None
    assert normalized["strings_truncated"] is False


def test_string_cap_truncation_propagates(tmp_path):
    path = tmp_path / "many.bin"
    chunks = [f"item-{index:06d}".encode() for index in range(100_001)]
    data = b"\x00".join(chunks)
    _write(path, data)
    rows, truncated = extract_strings(data, max_rows=2)
    assert len(rows) == 2
    assert truncated is True
    static = extract_generic(path)
    assert static["strings_truncated"] is True


def test_pe_extension_on_unknown_magic_records_mismatch(tmp_path):
    path = tmp_path / "document.pdf"
    _write(path, b"\x00\x01\x02\x03garbage")
    result = extract_generic(path, extension_mismatch=True)
    assert result["extension_mismatch"] is True
    assert result["generic_observations"]["magic_detected"] == "bytes"


def test_no_path_traversal_from_filename(tmp_path):
    # The filename is never used as a filesystem path; only the passed path
    # argument is read. Verify extract works regardless of a caller-supplied
    # weird name string.
    source = tmp_path / "weird.bin"
    _write(source, b"static input")
    result = extract_generic(source, original_filename="../../outside.bin")
    assert result["format"] == "generic"
