import os
import shutil
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from uuid import UUID


class UnsafeStoragePath(ValueError):
    pass


_FUNCTION_ID = re.compile(r"^([0-9a-f-]+):(0x[0-9a-f]+)$")


def resolve_under(base: str | Path, *parts: str | os.PathLike[str]) -> Path:
    """Resolve a path beneath base, rejecting traversal and absolute components."""
    root = Path(base).expanduser().resolve()
    candidate = root
    for raw_part in parts:
        raw = os.fspath(raw_part)
        if not raw or "\x00" in raw:
            raise UnsafeStoragePath("Invalid storage path component")
        normalized = raw.replace("\\", "/")
        if ".." in PurePosixPath(normalized).parts or PureWindowsPath(raw).is_absolute() or PurePosixPath(normalized).is_absolute():
            raise UnsafeStoragePath("Path traversal is not allowed")
        candidate = candidate / raw
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise UnsafeStoragePath("Resolved path escapes the storage root") from exc
    return resolved


def analysis_id_component(analysis_id: str) -> str:
    try:
        return str(UUID(str(analysis_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise UnsafeStoragePath("Invalid analysis id") from exc


def upload_file_path(data_root: str | Path, analysis_id: str) -> Path:
    return resolve_under(Path(data_root) / "uploads", analysis_id_component(analysis_id), "original.bin")


def artifact_dir_path(data_root: str | Path, analysis_id: str) -> Path:
    return resolve_under(Path(data_root) / "artifacts", analysis_id_component(analysis_id))


def function_artifact_path(data_root: str | Path, analysis_id: str, fid: str) -> Path:
    """Return canonical full-decomp path after verifying the function owner."""
    analysis = analysis_id_component(analysis_id)
    match = _FUNCTION_ID.fullmatch(fid)
    if match is None:
        raise UnsafeStoragePath("Invalid function id")
    try:
        owner = str(UUID(match.group(1)))
    except ValueError as exc:
        raise UnsafeStoragePath("Invalid function id") from exc
    if owner != analysis:
        raise UnsafeStoragePath("Function does not belong to this analysis")
    return resolve_under(artifact_dir_path(data_root, analysis), "funcs", f"{match.group(2)[2:]}.c")


def ensure_storage_roots(data_root: str | Path) -> None:
    root = Path(data_root).expanduser().resolve()
    for child in ("uploads", "artifacts"):
        path = resolve_under(root, child)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            path.chmod(0o700)
        except OSError:
            pass


def create_upload_directory(data_root: str | Path, analysis_id: str) -> Path:
    path = upload_file_path(data_root, analysis_id).parent
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def remove_analysis_files(data_root: str | Path, analysis_id: str) -> None:
    upload_dir = upload_file_path(data_root, analysis_id).parent
    artifact_dir = artifact_dir_path(data_root, analysis_id)
    for path in (upload_dir, artifact_dir):
        if path.is_symlink():
            raise UnsafeStoragePath("Refusing to remove a symlinked analysis directory")
        if path.exists():
            shutil.rmtree(path)


def remove_temporary_artifacts(data_root: str | Path, analysis_id: str) -> None:
    temp_path = resolve_under(artifact_dir_path(data_root, analysis_id), "tmp")
    if temp_path.is_symlink():
        raise UnsafeStoragePath("Refusing to remove a symlinked temporary directory")
    if temp_path.exists():
        shutil.rmtree(temp_path)
