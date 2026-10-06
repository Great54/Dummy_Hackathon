"""Safe repository discovery, fingerprinting, and source chunk production."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from pathlib import Path

from app.rag.chunker import chunk_file
from app.rag.document import RepositoryChunk
from app.tools.repository_tool import discover_repository_files


def repository_fingerprint(root: Path, files: Iterable[Path]) -> str:
    entries = []
    for path in files:
        stat = path.stat()
        entries.append(
            (
                path.relative_to(root).as_posix(),
                stat.st_size,
                stat.st_mtime_ns,
            )
        )
    encoded = json.dumps(sorted(entries), separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def index_repository(
    root: Path,
    *,
    excluded_paths: set[Path] | None = None,
    check_cancelled: Callable[[], None] | None = None,
) -> tuple[str, list[RepositoryChunk], int]:
    files = discover_repository_files(root, excluded_paths=excluded_paths)
    fingerprint = repository_fingerprint(root, files)
    chunks: list[RepositoryChunk] = []
    check = check_cancelled or (lambda: None)

    for path in files:
        check()
        relative_path = path.relative_to(root).as_posix()
        chunks.extend(chunk_file(path, relative_path))

    check()
    return fingerprint, chunks, len(files)