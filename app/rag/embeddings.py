"""Lazy local embeddings used only for repository retrieval."""

from __future__ import annotations

import os
from typing import Protocol, Sequence

import numpy as np

DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class EmbeddingProvider(Protocol):
    @property
    def model_name(self) -> str: ...

    def encode(self, texts: Sequence[str]) -> np.ndarray: ...


class SentenceTransformerEmbeddings:
    def __init__(self, model_name: str | None = None) -> None:
        self._model_name = model_name or os.getenv(
            "RAG_EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL
        )
        self._model = None

    @property
    def model_name(self) -> str:
        return self._model_name

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        if not texts:
            return np.empty((0, 0), dtype="float32")
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            try:
                self._model = SentenceTransformer(
                    self._model_name, local_files_only=True
                )
            except OSError:
                self._model = SentenceTransformer(self._model_name)
        values = self._model.encode(
            list(texts),
            batch_size=32,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return np.asarray(values, dtype="float32")