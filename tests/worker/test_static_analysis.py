import copy
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from worker.lief_extract import InvalidBinary, extract_pe, shannon_entropy
from worker.normalize import NormalizationError, normalize_analysis, serialize_normalized, validate_normalized
from worker.strings import extract_strings


def _static():
    return {
        "sha256": "a" * 64,
        "md5": "b" * 32,
        "size": 12,
        "format": "pe",
        "arch": "x64",
        "bitness": 64,
        "endian": "le",
        "entry_point": "0x140001000",
        "original_filename": "hello_pe_x64.exe",
        "extension_mismatch": False,
        "sections": [
            {"name": ".text", "vaddr": "0x140001000", "vsize": 4, "raw_size": 4, "perms": "R-X", "entropy": 2.0}
        ],
        "imports": [
            {"library": "kernel32.dll", "name": "ExitProcess", "ordinal": None, "address": "0x140002000", "category": "process"}
        ],
        "exports": [],
        "strings": [{"offset": "0x4", "encoding": "utf-8", "value": "hello", "length": 5, "category": "other"}],
        "strings_truncated": False,
        "possible_packing": False,
        "packing_note": None,
    }


def test_entropy_known_byte_blocks():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(bytes(64)) == 0.0
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_invalid_pe_maps_to_parser_failure(tmp_path):
    malformed = tmp_path / "malformed.exe"
    malformed.write_bytes(b"MZ" + bytes(126))
    with pytest.raises(InvalidBinary, match="valid PE binary"):
        extract_pe(malformed)


def test_ascii_and_utf16_strings_keep_offsets_and_categories():
    data = b"xxhttps://example.test\x00\x00S\x00o\x00f\x00t\x00w\x00a\x00r\x00e\x00\\\x00R\x00u\x00n\x00"
    rows, truncated = extract_strings(data)
    assert truncated is False
    ascii_url = next(row for row in rows if row["encoding"] == "utf-8")
    assert ascii_url["offset"] == "0x0"
    assert ascii_url["category"] == "url"
    registry = next(row for row in rows if row["encoding"] == "utf-16le")
    expected_offset = data.index(bytes((ord("S"), 0, ord("o"), 0)))
    assert registry["offset"] == f"0x{expected_offset:x}"
    assert registry["category"] == "registry"
    assert registry["length"] == len(registry["value"])


def test_string_cap_sets_truncated_flag():
    rows, truncated = extract_strings(b"abcd\x00efgh\x00ijkl", max_rows=2)
    assert [row["value"] for row in rows] == ["abcd", "efgh"]
    assert truncated is True


def test_normalization_is_byte_deterministic_and_rejects_bad_data():
    analysis_id = str(uuid4())
    created_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    static = _static()
    first = serialize_normalized(normalize_analysis(static, analysis_id, created_at=created_at))
    second = serialize_normalized(normalize_analysis(copy.deepcopy(static), analysis_id, created_at=created_at))
    assert first == second

    malformed = normalize_analysis(static, analysis_id, created_at=created_at)
    malformed["sections"][0]["entropy"] = 9.0
    with pytest.raises(NormalizationError):
        validate_normalized(malformed)


def test_normalization_orders_and_deduplicates_imports_and_uses_null_addresses():
    static = _static()
    static["imports"].extend([
        {"library": "KERNEL32.DLL", "name": "exitprocess", "ordinal": None, "address": None, "category": "process"},
        {"library": "user32.dll", "name": "MessageBoxW", "ordinal": None, "address": None, "category": "other"},
    ])
    result = normalize_analysis(static, str(uuid4()), created_at=datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert len(result["imports"]) == 2
    assert next(row for row in result["imports"] if row["name"] == "MessageBoxW")["address"] is None
    validate_normalized(result)
