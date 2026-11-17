"""Stable, versioned cache for validated AI outputs.

Cache key = SHA-256 over canonical serialized input: model, prompt version,
schema version, and the normalized analysis input hash. Output is returned
only after schema and evidence validation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def cache_key(
    *,
    model: str,
    prompt_version: str,
    schema_version: str,
    input_hash: str,
) -> str:
    """Return a stable SHA-256 cache key for a validated AI result."""
    payload = {
        "model": model,
        "prompt_version": prompt_version,
        "schema_version": schema_version,
        "input_hash": input_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AICache:
    """In-memory cache of validated AI outputs keyed by deterministic input."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    def get(self, key: str) -> dict[str, Any] | None:
        return self._store.get(key)

    def set(self, key: str, value: dict[str, Any]) -> None:
        self._store[key] = value

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()
