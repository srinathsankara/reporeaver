# SPDX-License-Identifier: MIT
"""Ingesters for single files, directories, and archives (including nested)."""

import io
import logging
import tarfile
import zipfile
from pathlib import Path
from typing import List, Optional, Set

log = logging.getLogger("reporeaver.ingest")

from ..models import FileEntry
from ..utils.known import ARCHIVE_EXTS, CONFIG_EXTS, SCRIPT_EXTS
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
TOTAL_MAX_SIZE = 500 * 1024 * 1024  # 500MB total decompressed limit
MAX_FILE_COUNT = 10_000  # prevent zip bomb metadata exhaustion
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
            try:
                rel = str(p.relative_to(root)).replace("\\", "/")
            except ValueError:
                continue
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


def _should_skip_name(name: str) -> bool:
    if ".." in Path(name).parts or name.startswith("/") or ":" in name:
        log.debug("Skipping path traversal entry: %s", name)
        return True
    if any(seg in IGNORE_DIRS for seg in name.split("/")):
        return True
    if Path(name).suffix.lower() in IGNORE_EXTS:
        return True
    return False


def _is_bomb(files: list, total_size: int, name: str) -> bool:
    if len(files) >= MAX_FILE_COUNT:
        log.warning("Archive bomb: too many files")
        return True
    if total_size > TOTAL_MAX_SIZE:
        log.warning("Archive bomb: total size exceeds limit near %s", name)
        return True
    return False


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
    total_size = 0
    try:
        with zipfile.ZipFile(str(path)) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if _should_skip_name(name):
                    continue
                if info.file_size > MAX_FILE_SIZE:
                    continue
                total_size += info.file_size
                if _is_bomb(files, total_size, path.name):
                    break
                ext = Path(name).suffix.lower()
                # Check for nested archive (stream with decompression cap)
                if ext in ARCHIVE_EXTS and depth < 3:
                    try:
                        with z.open(name) as zf:
                            total_read = 0
                            chunks = []
                            while True:
                                chunk = zf.read(65536)
                                if not chunk:
                                    break
                                total_read += len(chunk)
                                if total_read > TOTAL_MAX_SIZE:
                                    log.warning("Nested archive decompression exceeded limit for %s", name)
                                    raise MemoryError("decompression bomb")
                                chunks.append(chunk)
                        raw = b"".join(chunks)
                        nested = _extract_archive_bytes(raw, name, depth + 1)
                        files.extend(nested.files)
                        continue
                    except MemoryError:
                        raise
                    except Exception as exc:
                        log.debug("Nested zip extract failed for %s: %s", name, exc)
                mime = guess_mime(name)
                entry = _build_entry(name, info.file_size, mime, ext)
                if entry:
                    files.append(entry)
    except MemoryError:
        raise
    except Exception as exc:
        log.debug("Zip ingest failed for %s: %s", path, exc)
    return IngestResult(files=files, source_type="zip", source_path=str(path))


def _ingest_tar(path: Path, depth: int = 0) -> IngestResult:
    files: List[FileEntry] = []
    total_size = 0
    try:
        mode = "r:gz" if path.suffix in (".gz", ".tgz") else "r"
        with tarfile.open(str(path), mode) as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                name = member.name
                if _should_skip_name(name):
                    continue
                if member.size > MAX_FILE_SIZE:
                    continue
                total_size += member.size
                if _is_bomb(files, total_size, path.name):
                    break
                ext = Path(name).suffix.lower()
                # Check for nested archive (stream with decompression cap)
                if ext in ARCHIVE_EXTS and depth < 3:
                    try:
                        f = tar.extractfile(member)
                        if f:
                            total_read = 0
                            chunks = []
                            while True:
                                chunk = f.read(65536)
                                if not chunk:
                                    break
                                total_read += len(chunk)
                                if total_read > TOTAL_MAX_SIZE:
                                    log.warning("Nested archive decompression exceeded limit for %s", name)
                                    raise MemoryError("decompression bomb")
                                chunks.append(chunk)
                            raw = b"".join(chunks)
                        else:
                            raw = b""
                        nested = _extract_archive_bytes(raw, name, depth + 1)
                        files.extend(nested.files)
                        continue
                    except MemoryError:
                        raise
                    except Exception as exc:
                        log.debug("Nested tar extract failed for %s: %s", name, exc)
                mime = guess_mime(name)
                entry = _build_entry(name, member.size, mime, ext)
                if entry:
                    files.append(entry)
    except MemoryError:
        raise
    except Exception as exc:
        log.debug("Tar ingest failed for %s: %s", path, exc)
    return IngestResult(files=files, source_type="tar", source_path=str(path))


def _extract_archive_bytes(data: bytes, name: str, depth: int) -> IngestResult:
    """Extract a nested archive from raw bytes. Handles both zip and tar."""
    if depth >= 3:
        return IngestResult(source_type="nested_too_deep")
    # Try nested ZIP
    if len(data) > 2 and zipfile.is_zipfile(io.BytesIO(data)):
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
        except Exception as exc:
            log.debug("Nested zip bytes extract failed: %s", exc)

    # Try nested tar
    if len(data) > 2:
        try:
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
        except Exception as exc:
            log.debug("Nested tar bytes extract failed: %s", exc)
    return IngestResult(source_type="nested_unknown")


def _make_entry(path: Path, rel: Optional[str] = None) -> Optional[FileEntry]:
    try:
        if path.is_symlink():
            log.debug("Skipping symlink: %s", path)
            return None
        fpath = rel or str(path).replace("\\", "/")
        size = path.stat().st_size
        mime = guess_mime(fpath)
        ext = path.suffix.lower()
        return _build_entry(fpath, size, mime, ext)
    except (OSError, FileNotFoundError):
        return None


def _build_entry(fpath: str, size: int, mime: str, ext: str) -> FileEntry:
    """Build a FileEntry (hash deferred to pipeline to avoid double read)."""
    fpath = fpath.replace("\\", "/")
    return FileEntry(
        path=fpath,
        size=size,
        detected_mime=mime,
        declared_ext=ext,
        is_text="text" in (mime or ""),
        is_svg=fpath.lower().endswith(".svg"),
        is_script=fpath.lower().endswith(tuple(SCRIPT_EXTS)),
        is_config=fpath.lower().endswith(tuple(CONFIG_EXTS)),
    )
