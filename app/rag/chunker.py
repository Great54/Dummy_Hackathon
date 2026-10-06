"""Bounded, line-aware chunking for repository text files."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from pathlib import Path

from app.rag.document import RepositoryChunk
from app.tools.repository_tool import redact_secrets

CHUNK_SIZE_LINES = 80
CHUNK_OVERLAP_LINES = 15
MAX_CHUNK_CHARACTERS = 8_000


def chunk_file(
    path: Path,
    relative_path: str,
    *,
    chunk_size_lines: int = CHUNK_SIZE_LINES,
    overlap_lines: int = CHUNK_OVERLAP_LINES,
    max_characters: int = MAX_CHUNK_CHARACTERS,
) -> Iterator[RepositoryChunk]:
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        yield from chunk_lines(
            stream,
            relative_path,
            chunk_size_lines=chunk_size_lines,
            overlap_lines=overlap_lines,
            max_characters=max_characters,
            file_size=path.stat().st_size,
        )


def chunk_lines(
    lines: Iterable[str],
    relative_path: str,
    *,
    chunk_size_lines: int = CHUNK_SIZE_LINES,
    overlap_lines: int = CHUNK_OVERLAP_LINES,
    max_characters: int = MAX_CHUNK_CHARACTERS,
    file_size: int | None = None,
) -> Iterator[RepositoryChunk]:
    if chunk_size_lines < 1 or max_characters < 1:
        raise ValueError("Chunk limits must be positive.")
    if overlap_lines < 0 or overlap_lines >= chunk_size_lines:
        raise ValueError("Chunk overlap must be smaller than the chunk size.")

    window: list[tuple[int, str]] = []
    character_count = 0
    last_emitted_end = 0

    for line_number, raw_line in enumerate(lines, start=1):
        line = redact_secrets(raw_line.rstrip("\r\n"))[:max_characters]
        if window and (
            len(window) >= chunk_size_lines
            or character_count + len(line) + 1 > max_characters
        ):
            yield _make_chunk(relative_path, window, file_size)
            last_emitted_end = window[-1][0]
            window = window[-overlap_lines:] if overlap_lines else []
            character_count = _text_length(window)
            while window and character_count + len(line) + 1 > max_characters:
                window.pop(0)
                character_count = _text_length(window)

        window.append((line_number, line))
        character_count += len(line) + (1 if len(window) > 1 else 0)

    if window and window[-1][0] > last_emitted_end:
        yield _make_chunk(relative_path, window, file_size)


def _make_chunk(
    relative_path: str,
    numbered_lines: list[tuple[int, str]],
    file_size: int | None,
) -> RepositoryChunk:
    text = "\n".join(text for _, text in numbered_lines)
    start_line = numbered_lines[0][0]
    end_line = numbered_lines[-1][0]
    identity = f"{relative_path}:{start_line}:{end_line}:{text}".encode(
        "utf-8", errors="replace"
    )
    return RepositoryChunk(
        path=relative_path,
        start_line=start_line,
        end_line=end_line,
        text=text,
        file_type=Path(relative_path).suffix.lower(),
        chunk_id=hashlib.sha256(identity).hexdigest()[:24],
        metadata={"extension": Path(relative_path).suffix.lower(), "file_size": file_size},
    )


def _text_length(numbered_lines: list[tuple[int, str]]) -> int:
    if not numbered_lines:
        return 0
    return sum(len(text) for _, text in numbered_lines) + len(numbered_lines) - 1