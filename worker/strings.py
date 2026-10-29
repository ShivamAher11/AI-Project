"""Bounded printable-string extraction with original file offsets."""

from __future__ import annotations

import re


MAX_STRINGS = 100_000
MIN_LENGTH = 4
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")


def categorize_string(value: str) -> str:
    lowered = value.casefold()
    if "software\\" in lowered or "currentversion\\run" in lowered or "runonce" in lowered:
        return "registry"
    if "http://" in lowered or "https://" in lowered or "ftp://" in lowered or "www." in lowered:
        return "url"
    if re.search(r"(?:[a-z]:\\|/[^\s]+|\\\\[^\\]+\\)", value, re.IGNORECASE):
        return "path"
    if any(token in lowered for token in ("cmd.exe", "powershell", " /c ", "-encodedcommand")):
        return "cmd"
    return "other"


def _utf16_runs(data: bytes):
    index = 0
    end = len(data)
    while index + 1 < end:
        # UTF-16LE printable ASCII subset is a printable byte followed by NUL.
        if 0x20 <= data[index] <= 0x7E and data[index + 1] == 0:
            start = index
            chars = bytearray()
            while index + 1 < end and 0x20 <= data[index] <= 0x7E and data[index + 1] == 0:
                chars.append(data[index])
                index += 2
            if len(chars) >= MIN_LENGTH:
                yield start, chars.decode("ascii"), len(chars)
        else:
            index += 1


def _ascii_rows(data: bytes):
    for match in _ASCII_RUN.finditer(data):
        value = match.group().decode("ascii")
        yield match.start(), "utf-8", {
            "offset": f"0x{match.start():x}", "encoding": "utf-8", "value": value,
            "length": len(value), "category": categorize_string(value),
        }


def _wide_rows(data: bytes):
    for offset, value, length in _utf16_runs(data):
        yield offset, "utf-16le", {
            "offset": f"0x{offset:x}", "encoding": "utf-16le", "value": value,
            "length": length, "category": categorize_string(value),
        }


def extract_strings(data: bytes, max_rows: int = MAX_STRINGS) -> tuple[list[dict], bool]:
    """Return globally offset-ordered rows (capped at 100k) and a truncation flag."""
    limit = max(0, min(int(max_rows), MAX_STRINGS))
    ascii_iter = iter(_ascii_rows(data))
    wide_iter = iter(_wide_rows(data))
    left = next(ascii_iter, None)
    right = next(wide_iter, None)
    result = []
    truncated = False
    while left is not None or right is not None:
        if right is None or (left is not None and (left[0], left[1]) <= (right[0], right[1])):
            item, left = left, next(ascii_iter, None)
        else:
            item, right = right, next(wide_iter, None)
        if len(result) >= limit:
            truncated = True
            break
        result.append(item[2])
    return result, truncated
