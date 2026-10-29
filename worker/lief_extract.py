"""Static PE x64 metadata extraction. This module never loads or executes input."""

from __future__ import annotations

import hashlib
import math
import json
from collections import Counter
from pathlib import Path

import lief

from worker.strings import extract_strings


class InvalidBinary(ValueError):
    pass


class UnsupportedArchitecture(ValueError):
    pass


MACHINE_AMD64 = 0x8664
PE32_PLUS = 0x20B
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
CATEGORY_LOOKUP = Path(__file__).resolve().parents[1] / "rules" / "import_categories.json"


def load_import_categories(path: Path = CATEGORY_LOOKUP) -> dict[str, str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {str(name).casefold(): str(category) for name, category in raw.items()}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 6)


def _hex_or_none(value: int | None) -> str | None:
    return None if value is None or int(value) == 0 else f"0x{int(value):x}"


def _hash_file(path: Path) -> tuple[str, str, int]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            sha256.update(block)
            md5.update(block)
    return sha256.hexdigest(), md5.hexdigest(), size


def _decode_name(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip("\x00")
    return str(value)


def _permission_string(characteristics: int) -> str:
    return "".join(
        (
            "R" if characteristics & IMAGE_SCN_MEM_READ else "-",
            "W" if characteristics & IMAGE_SCN_MEM_WRITE else "-",
            "X" if characteristics & IMAGE_SCN_MEM_EXECUTE else "-",
        )
    )


def _category(name: str, categories: dict[str, str]) -> str:
    return categories.get(name.casefold(), "other")


def _extract_pe_content(path: str | Path, *, original_filename: str = "upload", extension_mismatch: bool = False,
                        categories: dict[str, str] | None = None) -> dict:
    """Parse PE x64 metadata from disk and return JSON-compatible static records."""
    source = Path(path)
    sha256, md5, size = _hash_file(source)
    try:
        config = lief.PE.ParserConfig()
        config.parse_imports = True
        config.parse_exports = True
        binary = lief.PE.parse(source, config)
    except Exception as exc:
        raise InvalidBinary("The uploaded file could not be parsed as a valid PE binary.") from exc
    if binary is None:
        raise InvalidBinary("The uploaded file could not be parsed as a valid PE binary.")

    machine = int(binary.header.machine)
    magic = int(binary.optional_header.magic)
    if machine != MACHINE_AMD64 or magic != PE32_PLUS:
        # TODO(spec §13): add ELF, x86-32, and ARM only after explicit scope approval.
        raise UnsupportedArchitecture("Only PE x64 executables and libraries are supported currently.")

    imagebase = int(binary.optional_header.imagebase)
    entry_rva = int(binary.optional_header.addressof_entrypoint)
    sections = []
    for section in binary.sections:
        sections.append(
            {
                "name": _decode_name(section.name),
                "vaddr": f"0x{imagebase + int(section.virtual_address):x}",
                "vsize": int(section.virtual_size),
                "raw_size": int(section.sizeof_raw_data),
                "perms": _permission_string(int(section.characteristics)),
                "entropy": shannon_entropy(bytes(section.content)),
            }
        )
    sections.sort(key=lambda item: (int(item["vaddr"], 16), item["name"]))

    categories = categories or {}
    imports_by_key: dict[tuple[str, str], dict] = {}
    for library in binary.imports:
        library_name = _decode_name(library.name).lower()
        for entry in library.entries:
            ordinal = int(entry.ordinal) if entry.is_ordinal else None
            name = _decode_name(entry.name) if not entry.is_ordinal else f"ordinal_{ordinal}"
            key = (library_name.casefold(), name.casefold())
            record = {
                "library": library_name,
                "name": name,
                "ordinal": ordinal,
                "address": _hex_or_none(int(entry.iat_address)),
                "category": _category(name, categories),
            }
            existing = imports_by_key.get(key)
            if existing is None or (existing["address"] is None and record["address"] is not None):
                imports_by_key[key] = record
    imports = sorted(imports_by_key.values(), key=lambda item: (item["address"] is None,
                                                                int(item["address"] or "0", 16),
                                                                item["library"], item["name"]))

    exports = []
    export_directory = binary.get_export()
    if export_directory is not None:
        for entry in export_directory.entries:
            exports.append({
                "name": _decode_name(entry.name),
                "address": _hex_or_none(imagebase + int(entry.address)),
                "ordinal": int(entry.ordinal) if entry.ordinal is not None else None,
            })
    exports.sort(key=lambda item: (item["address"] is None,
                                   int(item["address"] or "0", 16), item["ordinal"] or 0, item["name"]))

    with source.open("rb") as stream:
        file_bytes = stream.read()
    extracted_strings, strings_truncated = extract_strings(file_bytes)
    high_entropy_section = any(section["entropy"] >= 7.5 for section in sections)
    abnormal_section = any(
        "W" in section["perms"] and "X" in section["perms"]
        or section["raw_size"] > 0 and section["vsize"] != section["raw_size"]
        for section in sections
    )
    return {
        "sha256": sha256,
        "md5": md5,
        "size": size,
        "format": "pe",
        "arch": "x64",
        "bitness": 64,
        "endian": "le",
        "entry_point": _hex_or_none(imagebase + entry_rva) if entry_rva else None,
        "original_filename": original_filename,
        "extension_mismatch": bool(extension_mismatch),
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "strings": extracted_strings,
        "strings_truncated": strings_truncated,
        "possible_packing": high_entropy_section and abnormal_section,
        "packing_note": "possible packing - heuristic, not proof" if high_entropy_section and abnormal_section else None,
    }


def extract_pe(path: str | Path, *, original_filename: str = "upload", extension_mismatch: bool = False,
               categories: dict[str, str] | None = None) -> dict:
    try:
        return _extract_pe_content(path, original_filename=original_filename,
                                   extension_mismatch=extension_mismatch, categories=categories)
    except (InvalidBinary, UnsupportedArchitecture):
        raise
    except OSError:
        raise
    except Exception as exc:
        raise InvalidBinary("The uploaded file could not be parsed as a valid PE binary.") from exc
