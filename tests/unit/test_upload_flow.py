import asyncio
import json
import os
import stat
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import storage
from app.api.v1 import analyses as analyses_api
from app.db import new_session
from app.main import app
from app.models import Analysis


def _upload(client: TestClient, body: bytes, filename: str = "sample.exe"):
    return client.post(
        "/api/v1/analyses",
        files={"file": (filename, body, "application/octet-stream")},
    )


def _read_events(response_text: str):
    events = []
    current = {"name": None, "data": None}
    for line in response_text.splitlines():
        if line.startswith("event: "):
            current["name"] = line[7:]
        elif line.startswith("data: "):
            current["data"] = json.loads(line[6:])
        elif not line and current["name"]:
            events.append(current)
            current = {"name": None, "data": None}
    if current["name"]:
        events.append(current)
    return events


def test_upload_accepts_arbitrary_extension_within_limit(monkeypatch):
    with TestClient(app) as client:
        # Unknown magic with arbitrary extension is accepted (generic fallback).
        uploaded = _upload(client, b"PK\x03\x04fake zip", "archive.zip")
        assert uploaded.status_code == 201
        first_id = uploaded.json()["id"]

        # Any regular file: arbitrary extension, non-binary content.
        uploaded = _upload(client, b"plain text file contents", "notes.txt")
        assert uploaded.status_code == 201

        # Empty file still rejected.
        empty = _upload(client, b"")
        assert (empty.status_code, empty.json()["error"]["code"]) == (
            400,
            "EMPTY_FILE",
        )

        monkeypatch.setattr(analyses_api, "MAX_FILE_BYTES", 16)
        monkeypatch.setattr(analyses_api, "CONTENT_LENGTH_OVERHEAD", 0)
        oversize = _upload(client, b"plain text" * 20, "notes.txt")
        assert (oversize.status_code, oversize.json()["error"]["code"]) == (
            413,
            "PAYLOAD_TOO_LARGE",
        )


def test_upload_path_safety_never_uses_filename(tmp_path):
    with TestClient(app) as client:
        # Traversal-like filename must not escape the UUID upload directory.
        uploaded = _upload(client, b"MZ" + b"\x00" * 10, "..\\display-only.exe")
        assert uploaded.status_code == 201
        first_id = uploaded.json()["id"]
        target = storage.upload_file_path(os.getenv("DATA_ROOT", "/data"), first_id)
        assert target.is_file()
        assert target.name == "original.bin"
        assert target.parent.name == first_id
        # Stat safe perms.
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        client.delete(f"/api/v1/analyses/{first_id}")


def test_streaming_size_counter_removes_partial_file(tmp_path):
    class Chunks:
        def __init__(self):
            self.parts = iter([b"MZ12", b"345678"])

        async def read(self, _size):
            return next(self.parts, b"")

    target = tmp_path / "job" / "original.bin"
    with pytest.raises(analyses_api.UploadTooLarge):
        asyncio.run(analyses_api._stream_upload(Chunks(), target, max_bytes=6))
    assert not target.exists()


def test_fake_pe_falls_back_to_generic_instead_of_invalid_binary():
    fake_pe = b"MZ" + (b"\x00" * 126)
    with TestClient(app) as client:
        # PE magic attempts LIEF; malformed PE falls back to generic static.
        uploaded = _upload(client, fake_pe, "..\\display-only.exe")
        assert uploaded.status_code == 201
        first_id = uploaded.json()["id"]
        first_uuid = uuid.UUID(first_id)
        target = storage.upload_file_path(os.getenv("DATA_ROOT", "/data"), first_id)
        assert target.is_file()
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

        # Duplicate content gets a new analysis id (no dedup).
        duplicate = _upload(client, fake_pe, "same-content.dll")
        assert duplicate.status_code == 201
        second_id = duplicate.json()["id"]
        assert first_id in duplicate.json()["prior_analysis_ids"]

        deleted = client.delete(f"/api/v1/analyses/{first_id}")
        assert deleted.status_code == 202
        assert deleted.json() == {"deleted": True}
        assert not target.exists()
        with new_session() as session:
            assert session.get(Analysis, first_uuid) is None
        assert client.delete(f"/api/v1/analyses/{first_id}").status_code == 404

        assert client.delete(f"/api/v1/analyses/{second_id}").status_code == 202
