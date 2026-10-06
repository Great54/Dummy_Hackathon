"""Serializable repository chunks and retrieval results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class RepositoryChunk:
    path: str
    start_line: int
    end_line: int
    text: str
    file_type: str
    chunk_id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RepositoryChunk":
        return cls(
            path=str(value["path"]),
            start_line=int(value["start_line"]),
            end_line=int(value["end_line"]),
            text=str(value["text"]),
            file_type=str(value["file_type"]),
            chunk_id=str(value["chunk_id"]),
            metadata=dict(value.get("metadata", {})),
        )


@dataclass(frozen=True)
class RetrievalResult:
    chunk: RepositoryChunk
    score: float
    retrieval_method: str
    exact_matches: tuple[str, ...] = ()