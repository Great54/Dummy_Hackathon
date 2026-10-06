"""Bounded hybrid retrieval over exact identifiers and vector similarity."""

from __future__ import annotations

from collections import Counter
from typing import Any

from app.orchestrator.evidence import Evidence
from app.rag.document import RetrievalResult
from app.rag.index import RepositoryVectorIndex
from app.tools.repository_tool import derive_search_targets

RAG_TOP_K = 8
RAG_MAX_CONTEXT_CHUNKS = 8
RAG_MAX_CONTEXT_CHARACTERS = 30_000
RAG_MAX_QUERY_CHARACTERS = 4_000
RAG_MIN_VECTOR_SCORE = 0.25
MAX_CHUNKS_PER_PATH = 2


def build_retrieval_query(
    defect_description: str,
    evidence: list[Evidence],
) -> tuple[str, list[str]]:
    targets = derive_search_targets(defect_description, evidence)
    log_summaries = [
        item.summary[:300]
        for item in evidence
        if not item.source.startswith("Repository") and item.severity != "error"
    ][:8]
    sections = [defect_description.strip()[:2_000]]
    if targets:
        sections.append("Important identifiers and terms: " + " ".join(targets))
    if log_summaries:
        sections.append("Observed log evidence: " + " ".join(log_summaries))
    return "\n".join(sections)[:RAG_MAX_QUERY_CHARACTERS], targets


class HybridRetriever:
    def __init__(self, vector_index: RepositoryVectorIndex) -> None:
        self.vector_index = vector_index

    def retrieve(
        self,
        query: str,
        *,
        exact_terms: list[str],
        keyword_matches: list[dict[str, Any]] | None = None,
        top_k: int = RAG_TOP_K,
        max_characters: int = RAG_MAX_CONTEXT_CHARACTERS,
    ) -> list[RetrievalResult]:
        limit = min(max(top_k, 0), RAG_MAX_CONTEXT_CHUNKS)
        if not query.strip() or limit == 0:
            return []

        candidates: dict[str, RetrievalResult] = {}
        for result in self.vector_index.search(query, max(limit * 4, limit)):
            if result.score >= RAG_MIN_VECTOR_SCORE:
                candidates[result.chunk.chunk_id] = result

        normalized_terms = [term.casefold() for term in exact_terms if term.strip()]
        keyword_locations = _keyword_locations(keyword_matches or [])
        for chunk in self.vector_index.chunks:
            lowered = chunk.text.casefold()
            exact = tuple(
                original
                for original, normalized in zip(exact_terms, normalized_terms)
                if normalized in lowered
            )
            location_match = any(
                chunk.start_line <= line <= chunk.end_line
                for line in keyword_locations.get(chunk.path, [])
            )
            if not exact and not location_match:
                continue
            existing = candidates.get(chunk.chunk_id)
            score = max(existing.score if existing else 0.0, 1.0 + 0.02 * len(exact))
            if location_match:
                score += 0.25
            methods = []
            if existing:
                methods.append("vector")
            if exact:
                methods.append("exact")
            if location_match:
                methods.append("keyword")
            candidates[chunk.chunk_id] = RetrievalResult(
                chunk=chunk,
                score=score,
                retrieval_method="+".join(methods),
                exact_matches=exact,
            )

        selected: list[RetrievalResult] = []
        path_counts: Counter[str] = Counter()
        used_characters = 0
        for result in sorted(
            candidates.values(),
            key=lambda item: (-item.score, item.chunk.path, item.chunk.start_line),
        ):
            if path_counts[result.chunk.path] >= MAX_CHUNKS_PER_PATH:
                continue
            if used_characters + len(result.chunk.text) > max_characters:
                continue
            selected.append(result)
            path_counts[result.chunk.path] += 1
            used_characters += len(result.chunk.text)
            if len(selected) >= limit:
                break
        return selected


def _keyword_locations(matches: list[dict[str, Any]]) -> dict[str, list[int]]:
    locations: dict[str, list[int]] = {}
    for match in matches:
        path = match.get("file")
        line = match.get("line")
        if isinstance(path, str) and isinstance(line, int):
            locations.setdefault(path, []).append(line)
    return locations