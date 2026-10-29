from pathlib import Path

import pytest

from app.storage import UnsafeStoragePath, function_artifact_path, resolve_under


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


def test_function_artifact_path_requires_matching_analysis_and_canonicalizes(tmp_path):
    analysis_id = "a1b2c3d4-e5f6-4789-8123-456789abcdef"
    path = function_artifact_path(tmp_path, analysis_id, f"{analysis_id}:0x140001000")
    assert path == (tmp_path / "artifacts" / analysis_id / "funcs" / "140001000.c").resolve()


@pytest.mark.parametrize("fid", [
    "../../outside:0x1", "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x../outside",
    "a1b2c3d4-e5f6-4789-8123-456789abcdee:0x1", "not-a-fid",
])
def test_function_artifact_path_rejects_traversal_and_other_owner(tmp_path, fid):
    with pytest.raises(UnsafeStoragePath):
        function_artifact_path(tmp_path, "a1b2c3d4-e5f6-4789-8123-456789abcdef", fid)
