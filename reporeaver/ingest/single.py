"""Ingesters for single files, directories, and archives (including nested)."""

import hashlib
import tarfile
import zipfile
from pathlib import Path
from typing import List, Optional, Set

from ..models import FileEntry
from ..utils.mime_detect import guess_mime
from .base import BaseIngester, IngestResult


IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".vscode", ".idea", "dist", "build", "target",
    "vendor", ".next", ".nuxt", ".cache",
}

IGNORE_EXTS = {
    ".pyc", ".pyo", ".pyd", ".so", ".dll", ".dylib",
    ".woff", ".woff2", ".ttf", ".eot",
    ".bin", ".o", ".a", ".lib", ".obj",
    ".map",
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per-file limit
ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".rar", ".7z"}


class SingleFileIngester(BaseIngester):
    def ingest(self, source: str) -> IngestResult:
        p = Path(source)
        entry = _make_entry(p)
        return IngestResult(files=[entry], source_type="file", source_path=source)


class DirectoryIngester(BaseIngester):
    def ingest(self, source: str) -> IngestResult:
        root = Path(source)
        files: List[FileEntry] = []
        seen: Set[str] = set()
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            rel = str(p.relative_to(root)).replace("\\", "/")
            if any(seg in IGNORE_DIRS for seg in rel.split("/")):
                continue
            if p.suffix.lower() in IGNORE_EXTS:
                continue
            try:
                if p.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            if rel in seen:
                continue
            seen.add(rel)
            entry = _make_entry(p, rel)
            if entry:
                files.append(entry)
        return IngestResult(files=files, source_type="directory", source_path=source)


class ArchiveIngester(BaseIngester):
    def ingest(self, source: str) -> IngestResult:
        p = Path(source)
        suffix = p.suffix.lower()
        if suffix in (".zip", ".gz", ".tgz", ".tar", ".rar", ".7z"):
            return _extract_archive_path(p)
        return IngestResult(source_type="archive", source_path=source)


def _extract_archive_path(path: Path, depth: int = 0) -> IngestResult:
    """Extract an archive, recursively handling nested archives."""
    if depth > 3:
        return IngestResult(source_type="archive", source_path=str(path))
    suffix = path.suffix.lower()
    if suffix == ".zip":
        return _ingest_zip(path, depth)
    if suffix in (".tar", ".gz", ".tgz"):
        return _ingest_tar(path, depth)
    return IngestResult(source_type="archive", source_path=str(path))


def _ingest_zip(path: Path, depth: int = 0) -> IngestResult:
    files: List[FileEntry] = []
    try:
        with zipfile.ZipFile(str(path)) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if any(seg in IGNORE_DIRS for seg in name.split("/")):
                    continue
                ext = Path(name).suffix.lower()
                if ext in IGNORE_EXTS:
                    continue
                if info.file_size > MAX_FILE_SIZE:
                    continue
                # Check for nested archive
                if ext in ARCHIVE_EXTS and depth < 3:
                    try:
                        raw = z.read(name)
                        nested = _extract_archive_bytes(raw, name, depth + 1)
                        files.extend(nested.files)
                        continue
                    except Exception:
                        pass
                mime = guess_mime(name)
                entry = _build_entry(name, info.file_size, mime, ext)
                if entry:
                    files.append(entry)
    except Exception:
        pass
    return IngestResult(files=files, source_type="zip", source_path=str(path))


def _ingest_tar(path: Path, depth: int = 0) -> IngestResult:
    files: List[FileEntry] = []
    try:
        mode = "r:gz" if path.suffix in (".gz", ".tgz") else "r"
        with tarfile.open(str(path), mode) as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                name = member.name
                if any(seg in IGNORE_DIRS for seg in name.split("/")):
                    continue
                ext = Path(name).suffix.lower()
                if ext in IGNORE_EXTS:
                    continue
                if member.size > MAX_FILE_SIZE:
                    continue
                # Check for nested archive
                if ext in ARCHIVE_EXTS and depth < 3:
                    try:
                        f = tar.extractfile(member)
                        raw = f.read() if f else b""
                        nested = _extract_archive_bytes(raw, name, depth + 1)
                        files.extend(nested.files)
                        continue
                    except Exception:
                        pass
                mime = guess_mime(name)
                entry = _build_entry(name, member.size, mime, ext)
                if entry:
                    files.append(entry)
    except Exception:
        pass
    return IngestResult(files=files, source_type="tar", source_path=str(path))


def _extract_archive_bytes(data: bytes, name: str, depth: int) -> IngestResult:
    """Extract a nested archive from raw bytes. Handles both zip and tar."""
    if depth >= 3:
        return IngestResult(source_type="nested_too_deep")
    import io

    # Try nested ZIP
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                files = []
                for info in z.infolist():
                    if info.is_dir():
                        continue
                    fname = f"{Path(name).stem}/{info.filename}"
                    if any(seg in IGNORE_DIRS for seg in fname.split("/")):
                        continue
                    ext = Path(fname).suffix.lower()
                    if ext in IGNORE_EXTS or ext in ARCHIVE_EXTS:
                        continue
                    mime = guess_mime(fname)
                    entry = _build_entry(fname, info.file_size, mime, ext)
                    if entry:
                        files.append(entry)
                return IngestResult(files=files, source_type="nested_zip")
        except Exception:
            pass
    # Try nested tar
    if len(data) > 2:
        try:
            import tarfile
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
                files = []
                for member in tar.getmembers():
                    if not member.isfile():
                        continue
                    fname = f"{Path(name).stem}/{member.name}"
                    if any(seg in IGNORE_DIRS for seg in fname.split("/")):
                        continue
                    ext = Path(fname).suffix.lower()
                    if ext in IGNORE_EXTS or ext in ARCHIVE_EXTS:
                        continue
                    mime = guess_mime(fname)
                    entry = _build_entry(fname, member.size, mime, ext)
                    if entry:
                        files.append(entry)
                return IngestResult(files=files, source_type="nested_tar")
        except Exception:
            pass
    return IngestResult(source_type="nested_unknown")


def _make_entry(path: Path, rel: Optional[str] = None) -> Optional[FileEntry]:
    try:
        fpath = rel or str(path).replace("\\", "/")
        size = path.stat().st_size
        mime = guess_mime(fpath)
        ext = path.suffix.lower()
        return _build_entry(fpath, size, mime, ext, path)
    except (OSError, FileNotFoundError):
        return None


def _build_entry(fpath: str, size: int, mime: str, ext: str,
                 disk_path: Optional[Path] = None) -> Optional[FileEntry]:
    """Build a FileEntry with optional SHA-256 hash."""
    hash_val = None
    if disk_path and size < MAX_FILE_SIZE and size > 0:
        try:
            h = hashlib.sha256()
            with open(disk_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            hash_val = h.hexdigest()
        except Exception:
            pass

    return FileEntry(
        path=fpath,
        size=size,
        detected_mime=mime,
        declared_ext=ext,
        hash_sha256=hash_val,
        is_text="text" in (mime or ""),
        is_svg=fpath.lower().endswith(".svg"),
        is_script=fpath.lower().endswith((".js", ".jsx", ".ts", ".tsx",
                                          ".py", ".sh", ".ps1", ".bat")),
        is_config=fpath.lower().endswith((".json", ".yaml", ".yml",
                                          ".toml", ".ini", ".conf")),
    )
