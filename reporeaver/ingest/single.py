"""Ingesters for single files, directories, and archives."""

import hashlib
import tarfile
import zipfile
from pathlib import Path
from typing import List, Optional

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
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".bin",
    ".exe", ".msi", ".deb", ".rpm",
    ".o", ".a", ".lib", ".obj",
    ".map", ".min.js",
}

MAX_FILE_SIZE = 5 * 1024 * 1024


class SingleFileIngester(BaseIngester):
    def ingest(self, source: str) -> IngestResult:
        p = Path(source)
        entry = _make_entry(p)
        return IngestResult(files=[entry], source_type="file", source_path=source)


class DirectoryIngester(BaseIngester):
    def ingest(self, source: str) -> IngestResult:
        root = Path(source)
        files: List[FileEntry] = []
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
            entry = _make_entry(p, rel)
            if entry:
                files.append(entry)
        return IngestResult(files=files, source_type="directory", source_path=source)


class ArchiveIngester(BaseIngester):
    def ingest(self, source: str) -> IngestResult:
        p = Path(source)
        suffix = p.suffix.lower()
        if suffix == ".zip":
            return self._ingest_zip(p)
        if suffix in (".tar", ".gz", ".tgz"):
            return self._ingest_tar(p)
        return IngestResult(source_type="archive", source_path=source)

    def _ingest_zip(self, path: Path) -> IngestResult:
        files = []
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
                    mime = guess_mime(name)
                    files.append(FileEntry(
                        path=name,
                        size=info.file_size,
                        detected_mime=mime,
                        declared_ext=ext,
                        is_text="text" in (mime or ""),
                        is_svg=name.lower().endswith(".svg"),
                        is_script=name.lower().endswith((".js", ".jsx", ".ts", ".tsx",
                                                          ".py", ".sh", ".ps1", ".bat")),
                        is_config=name.lower().endswith((".json", ".yaml", ".yml",
                                                          ".toml", ".ini", ".conf")),
                    ))
        except Exception:
            pass
        return IngestResult(files=files, source_type="zip", source_path=str(path))

    def _ingest_tar(self, path: Path) -> IngestResult:
        files = []
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
                    mime = guess_mime(name)
                    files.append(FileEntry(
                        path=name,
                        size=member.size,
                        detected_mime=mime,
                        declared_ext=ext,
                        is_text="text" in (mime or ""),
                        is_svg=name.lower().endswith(".svg"),
                        is_script=name.lower().endswith((".js", ".jsx", ".ts", ".tsx",
                                                          ".py", ".sh", ".ps1", ".bat")),
                        is_config=name.lower().endswith((".json", ".yaml", ".yml",
                                                          ".toml", ".ini", ".conf")),
                    ))
        except Exception:
            pass
        return IngestResult(files=files, source_type="tar", source_path=str(path))


def _make_entry(path: Path, rel: Optional[str] = None) -> Optional[FileEntry]:
    try:
        fpath = rel or str(path).replace("\\", "/")
        mime = guess_mime(fpath)
        ext = path.suffix.lower()
        return FileEntry(
            path=fpath,
            size=path.stat().st_size,
            detected_mime=mime,
            declared_ext=ext,
            is_text="text" in (mime or ""),
            is_svg=fpath.lower().endswith(".svg"),
            is_script=fpath.lower().endswith((".js", ".jsx", ".ts", ".tsx",
                                              ".py", ".sh", ".ps1", ".bat")),
            is_config=fpath.lower().endswith((".json", ".yaml", ".yml",
                                              ".toml", ".ini", ".conf")),
        )
    except (OSError, FileNotFoundError):
        return None
