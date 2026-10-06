"""Repository RAG tool integrated with deterministic analysis evidence."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, Optional

from app.orchestrator.cancellation import AnalysisCancelledError
from app.orchestrator.evidence import Evidence
from app.rag.index import RepositoryVectorIndex
from app.rag.retriever import HybridRetriever, build_retrieval_query
from app.tools.base import AnalysisTool
from input.models import AnalysisRequest

logger = logging.getLogger(__name__)


class RagRepositoryTool(AnalysisTool):
    name = "Repository RAG"
    phase = 110

    def __init__(self, vector_index: RepositoryVectorIndex | None = None) -> None:
        self._vector_index = vector_index
        self._cancelled = False

    def is_applicable(self, request: AnalysisRequest) -> bool:
        enabled = os.getenv("RAG_ENABLED", "true").strip().lower() not in {
            "0", "false", "no", "off"
        }
        path = Path(request.repo_path)
        return enabled and path.exists() and path.is_dir()

    def cancel(self) -> None:
        self._cancelled = True

    def run(
        self,
        request: AnalysisRequest,
        on_progress: Optional[Callable[[str], None]] = None,
        prior_evidence: Optional[list[Evidence]] = None,
    ) -> Evidence:
        self._cancelled = False
        prior = prior_evidence or []
        try:
            root = Path(request.repo_path).resolve(strict=True)
            self._report(on_progress, "Checking repository index...")
            vector_index = self._vector_index or RepositoryVectorIndex()
            self._vector_index = vector_index
            excluded_paths = {
                Path(path).resolve(strict=False)
                for path in (
                    request.blf_path,
                    request.mf4_path,
                    request.pcapng_path,
                    request.ttl_path,
                )
                if path
            }
            cache_status = vector_index.ensure(
                root,
                excluded_paths=excluded_paths,
                check_cancelled=self._check_cancelled,
                on_progress=on_progress,
            )
            self._check_cancelled()
            self._report(on_progress, "Retrieving relevant repository context...")
            query, exact_terms = build_retrieval_query(
                request.defect_description, prior
            )
            keyword_matches = _repository_keyword_matches(prior)
            results = HybridRetriever(vector_index).retrieve(
                query,
                exact_terms=exact_terms,
                keyword_matches=keyword_matches,
            )
            self._check_cancelled()
            self._report(on_progress, "Combining repository and log evidence...")
            chunks = [
                {
                    "path": result.chunk.path,
                    "start_line": result.chunk.start_line,
                    "end_line": result.chunk.end_line,
                    "extension": result.chunk.file_type,
                    "score": round(result.score, 6),
                    "retrieval_method": result.retrieval_method,
                    "exact_matches": list(result.exact_matches),
                    "text": result.chunk.text,
                }
                for result in results
            ]
            return Evidence(
                source=self.name,
                summary=(
                    f"Hybrid repository retrieval returned {len(chunks)} bounded "
                    "source/configuration chunks."
                ),
                details={
                    "retrieval_query": query,
                    "chunks": chunks,
                    "chunks_returned": len(chunks),
                    "keyword_matches_used": len(keyword_matches),
                    "index_status": cache_status,
                    "embedding_model": vector_index.embeddings.model_name,
                    "evidence_found": bool(chunks),
                    "repository_content_complete": False,
                    "limits": {"max_chunks": 8, "max_context_characters": 30_000},
                },
                severity="info",
            )
        except AnalysisCancelledError:
            raise
        except Exception as error:  # noqa: BLE001 - deterministic fallback is required
            logger.exception("Repository RAG unavailable")
            self._report(
                on_progress,
                "RAG retrieval unavailable; continuing with deterministic repository evidence.",
            )
            return Evidence(
                source=self.name,
                summary=(
                    "RAG retrieval unavailable; deterministic repository evidence "
                    "remains available."
                ),
                details={"evidence_found": False, "unavailable": True},
                severity="warning",
            )

    def _check_cancelled(self) -> None:
        if self._cancelled:
            raise AnalysisCancelledError("Analysis cancelled by the user.")

    @staticmethod
    def _report(
        callback: Optional[Callable[[str], None]], message: str
    ) -> None:
        if callback:
            callback(message)


def _repository_keyword_matches(evidence: list[Evidence]) -> list[dict[str, Any]]:
    for item in evidence:
        if item.source == "Repository Analysis":
            matches = item.details.get("matches", [])
            return matches if isinstance(matches, list) else []
    return []