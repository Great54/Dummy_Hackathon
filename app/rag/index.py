"""Persistent repository FAISS index with fingerprint validation."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np

from app.rag.document import RepositoryChunk, RetrievalResult
from app.rag.embeddings import EmbeddingProvider, SentenceTransformerEmbeddings
from app.rag.repository_indexer import index_repository, repository_fingerprint
from app.tools.repository_tool import discover_repository_files

INDEX_FORMAT_VERSION = 1
DEFAULT_CACHE_ROOT = Path(__file__).resolve().parents[2] / ".cache" / "rag"
EMBEDDING_BATCH_SIZE = 64


class RepositoryVectorIndex:
    def __init__(
        self,
        *,
        cache_root: Path | None = None,
        embeddings: EmbeddingProvider | None = None,
    ) -> None:
        configured_cache = os.getenv("RAG_CACHE_DIR")
        self.cache_root = Path(configured_cache) if configured_cache else (
            cache_root or DEFAULT_CACHE_ROOT
        )
        self.embeddings = embeddings or SentenceTransformerEmbeddings()
        self.chunks: list[RepositoryChunk] = []
        self._index = None
        self._fingerprint = ""

    def ensure(
        self,
        repository: Path,
        *,
        excluded_paths: set[Path] | None = None,
        check_cancelled: Callable[[], None] | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> str:
        root = repository.resolve(strict=True)
        files = discover_repository_files(root, excluded_paths=excluded_paths)
        fingerprint = repository_fingerprint(root, files)
        cache_directory = self._cache_directory(root)
        manifest_path = cache_directory / "manifest.json"
        manifest = self._read_manifest(manifest_path)

        if self._manifest_matches(manifest, root, fingerprint):
            try:
                self._load(cache_directory, manifest)
            except (OSError, RuntimeError, ValueError):
                self._index = None
                self.chunks = []
            else:
                if on_progress:
                    on_progress("Using cached repository RAG index...")
                return "cached"

        if on_progress:
            on_progress("Updating repository RAG index...")
        fingerprint, chunks, files_indexed = index_repository(
            root,
            excluded_paths=excluded_paths,
            check_cancelled=check_cancelled,
        )
        self._build(chunks, check_cancelled)
        self.chunks = chunks
        self._fingerprint = fingerprint
        self._save(cache_directory, root, fingerprint, files_indexed)
        return "rebuilt"

    def search(self, query: str, top_k: int) -> list[RetrievalResult]:
        if not query.strip() or top_k <= 0 or self._index is None or not self.chunks:
            return []
        import faiss

        query_vector = self.embeddings.encode([query])
        query_vector = np.asarray(query_vector, dtype="float32")
        faiss.normalize_L2(query_vector)
        scores, identifiers = self._index.search(
            query_vector, min(top_k, len(self.chunks))
        )
        results = []
        for score, identifier in zip(scores[0], identifiers[0]):
            if identifier < 0:
                continue
            results.append(
                RetrievalResult(
                    chunk=self.chunks[int(identifier)],
                    score=float(score),
                    retrieval_method="vector",
                )
            )
        return results

    def _build(
        self,
        chunks: list[RepositoryChunk],
        check_cancelled: Callable[[], None] | None,
    ) -> None:
        if not chunks:
            self._index = None
            return
        if check_cancelled:
            check_cancelled()
        import faiss

        batches = []
        for start in range(0, len(chunks), EMBEDDING_BATCH_SIZE):
            if check_cancelled:
                check_cancelled()
            batch = chunks[start:start + EMBEDDING_BATCH_SIZE]
            batches.append(
                np.asarray(
                    self.embeddings.encode([chunk.text for chunk in batch]),
                    dtype="float32",
                )
            )
        vectors = np.concatenate(batches, axis=0)
        if vectors.ndim != 2 or vectors.shape[0] != len(chunks):
            raise ValueError("Embedding provider returned an invalid matrix.")
        faiss.normalize_L2(vectors)
        index = faiss.IndexFlatIP(vectors.shape[1])
        index.add(vectors)
        if check_cancelled:
            check_cancelled()
        self._index = index

    def _save(
        self,
        cache_directory: Path,
        root: Path,
        fingerprint: str,
        files_indexed: int,
    ) -> None:
        import faiss

        cache_directory.mkdir(parents=True, exist_ok=True)
        index_name = f"index-{fingerprint}.faiss" if self._index is not None else None
        if index_name:
            index_path = cache_directory / index_name
            temporary_index = index_path.with_suffix(".faiss.tmp")
            faiss.write_index(self._index, str(temporary_index))
            temporary_index.replace(index_path)

        manifest = {
            "format_version": INDEX_FORMAT_VERSION,
            "repository_path": str(root),
            "repository_fingerprint": fingerprint,
            "embedding_model": self.embeddings.model_name,
            "index_file": index_name,
            "files_indexed": files_indexed,
            "chunks": [chunk.to_dict() for chunk in self.chunks],
        }
        manifest_path = cache_directory / "manifest.json"
        temporary_manifest = cache_directory / "manifest.json.tmp"
        temporary_manifest.write_text(
            json.dumps(manifest, ensure_ascii=True, separators=(",", ":")),
            encoding="utf-8",
        )
        temporary_manifest.replace(manifest_path)
        for stale in cache_directory.glob("index-*.faiss"):
            if stale.name != index_name:
                stale.unlink(missing_ok=True)

    def _load(self, cache_directory: Path, manifest: dict[str, Any]) -> None:
        import faiss

        self.chunks = [RepositoryChunk.from_dict(item) for item in manifest["chunks"]]
        self._fingerprint = str(manifest["repository_fingerprint"])
        index_name = manifest.get("index_file")
        if not index_name:
            self._index = None
            return
        if Path(index_name).name != index_name:
            raise ValueError("Invalid cached index path.")
        self._index = faiss.read_index(str(cache_directory / index_name))
        if self._index.ntotal != len(self.chunks):
            raise ValueError("Cached vector and metadata counts do not match.")

    def _manifest_matches(
        self,
        manifest: dict[str, Any] | None,
        root: Path,
        fingerprint: str,
    ) -> bool:
        if not manifest:
            return False
        index_name = manifest.get("index_file")
        index_exists = not index_name or (
            Path(index_name).name == index_name
            and (self._cache_directory(root) / index_name).is_file()
        )
        return bool(
            manifest.get("format_version") == INDEX_FORMAT_VERSION
            and manifest.get("repository_path") == str(root)
            and manifest.get("repository_fingerprint") == fingerprint
            and manifest.get("embedding_model") == self.embeddings.model_name
            and isinstance(manifest.get("chunks"), list)
            and index_exists
        )

    def _cache_directory(self, root: Path) -> Path:
        key = hashlib.sha256(str(root).casefold().encode("utf-8")).hexdigest()[:24]
        return self.cache_root / key

    @staticmethod
    def _read_manifest(path: Path) -> dict[str, Any] | None:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None