from pathlib import Path

import pytest

from app.storage import UnsafeStoragePath, resolve_under


@pytest.mark.parametrize("component", ["../outside", "..\\outside", "C:\\outside", "/outside"])
def test_storage_rejects_traversal_and_absolute_paths(tmp_path, component):
    with pytest.raises(UnsafeStoragePath):
        resolve_under(tmp_path, component)


def test_storage_rejects_symlink_escape(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "job"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation is unavailable")
    with pytest.raises(UnsafeStoragePath):
        resolve_under(root, "job", "original.bin")


def test_storage_resolves_safe_child(tmp_path):
    assert resolve_under(tmp_path, "job-id", "original.bin") == (tmp_path / "job-id" / "original.bin").resolve()
