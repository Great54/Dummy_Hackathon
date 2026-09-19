"""Incremental, bounded analysis of Turtle (TTL) definition files."""

from __future__ import annotations

import heapq
import logging
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Optional

from app.orchestrator.evidence import Evidence
from app.tools.base import AnalysisTool
from app.tools.ttl_trace_tool import is_tttech_ttl
from input.models import AnalysisRequest

logger = logging.getLogger(__name__)

MAX_PREFIXES = 100
MAX_NAMESPACES = 100
MAX_DEFINITION_EXAMPLES = 25
MAX_RELEVANT_MATCHES = 30
MAX_KEYWORDS = 30
MAX_SNIPPET_LENGTH = 300
DIAGNOSTIC_LINE_INTERVAL = 100_000
FORMAT_SAMPLE_BYTES = 65_536

PREFIX_PATTERN = re.compile(
    r"^\s*(?:@prefix\s+([\w-]*):\s*<([^>]+)>\s*\.|PREFIX\s+([\w-]*):\s*<([^>]+)>)",
    re.IGNORECASE,
)
SUBJECT_PATTERN = re.compile(r"^\s*([^\s#][^\s]*)\s+(?:a|rdf:type)\s+([^;,.]+)")
TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_/-]{2,}")

CATEGORY_TERMS = {
    "service_definitions": ("someip", "some/ip", "service", "method", "eventgroup"),
    "message_definitions": ("message", "frame", "pdu", "payload", "packet"),
    "signal_definitions": ("signal", "measurement", "parameter"),
    "network_definitions": ("ethernet", "udp", "tcp", "ipv4", "ipv6", "socket"),
    "datatype_definitions": ("datatype", "data type", "enumeration", "enum", "unit"),
    "relationship_definitions": ("relation", "relationship", "maps", "contains", "belongs"),
}


class TtlAnalysisError(RuntimeError):
    """Controlled error raised when a TTL file cannot be analyzed."""


class TtlTool(AnalysisTool):
    """Extract compact structural and defect-aware evidence from a TTL file."""

    name = "TTL Analysis"

    def is_applicable(self, request: AnalysisRequest) -> bool:
        return bool(
            request.ttl_path and not is_tttech_ttl(Path(request.ttl_path))
        )

    def run(
        self,
        request: AnalysisRequest,
        on_progress: Optional[Callable[[str], None]] = None,
        prior_evidence: Optional[list[Evidence]] = None,
    ) -> Evidence:
        path = self._validate_path(request.ttl_path)
        logger.info(
            "TTL diagnostic: starting path=%s size_bytes=%d",
            path,
            path.stat().st_size,
        )
        started = time.perf_counter()
        try:
            self._validate_supported_format(path)
            details = self._scan(path, request.defect_description)
        except PermissionError as error:
            logger.exception("Permission denied reading TTL file %s", path)
            raise TtlAnalysisError(f"Permission denied reading TTL file: {path}") from error
        except OSError as error:
            logger.exception("Unable to read TTL file %s", path)
            raise TtlAnalysisError(f"Unable to read TTL file: {error}") from error

        logger.info(
            "TTL diagnostic: completed lines=%d elapsed_seconds=%.3f",
            details["line_count"],
            time.perf_counter() - started,
        )

        relevant_count = len(details["relevant_matches"])
        summary = (
            f"Scanned {details['line_count']} TTL lines incrementally; found "
            f"{details['prefix_count']} prefix declarations, "
            f"{details['definition_count']} typed definitions, and "
            f"{relevant_count} bounded defect-relevant matches."
        )
        return Evidence(
            source="TTL Analysis",
            summary=summary,
            details=details,
            severity="info",
        )

    @staticmethod
    def _validate_supported_format(path: Path) -> None:
        with path.open("rb") as stream:
            sample = stream.read(FORMAT_SAMPLE_BYTES)

        control_bytes = sum(
            byte < 9 or 13 < byte < 32
            for byte in sample
        )
        binary_ratio = control_bytes / len(sample) if sample else 0.0
        logger.info(
            "TTL diagnostic: format probe magic=%r sample_bytes=%d "
            "binary_control_ratio=%.4f",
            sample[:4],
            len(sample),
            binary_ratio,
        )

        if sample.startswith(b"TTL ") or b"\x00" in sample or binary_ratio > 0.01:
            raise TtlAnalysisError(
                "The selected .ttl file is a binary TTTech trace container, not "
                "an RDF/Turtle text definition file. Binary TTTech TTL parsing is "
                "not implemented yet; the file was not scanned as text."
            )

    @staticmethod
    def _validate_path(path_text: str | None) -> Path:
        if not path_text:
            raise TtlAnalysisError("No TTL path was supplied.")
        path = Path(path_text)
        if path.suffix.lower() != ".ttl":
            raise TtlAnalysisError(f"Selected file is not a .ttl file: {path}")
        if not path.exists():
            raise TtlAnalysisError(f"TTL file does not exist: {path}")
        if not path.is_file():
            raise TtlAnalysisError(f"TTL path is not a file: {path}")
        return path

    def _scan(self, path: Path, defect_description: str) -> dict[str, Any]:
        scan_started = time.perf_counter()
        prefixes: dict[str, str] = {}
        namespaces: set[str] = set()
        categories: Counter[str] = Counter()
        relevant_keyword_counts: Counter[str] = Counter()
        definition_examples: list[dict[str, Any]] = []
        relevant_heap: list[tuple[int, int, dict[str, Any]]] = []
        defect_keywords = _defect_keywords(defect_description)
        sequence = 0
        line_count = 0
        definition_count = 0
        truncated_lines = 0
        characters_processed = 0

        logger.info(
            "TTL diagnostic: scan setup keywords=%d categories=%d",
            len(defect_keywords),
            sum(len(terms) for terms in CATEGORY_TERMS.values()),
        )

        with path.open("r", encoding="utf-8", errors="replace") as stream:
            logger.info("TTL diagnostic: file opened; beginning single-pass scan")
            for line_number, raw_line in enumerate(stream, start=1):
                line_count = line_number
                characters_processed += len(raw_line)
                if line_number % DIAGNOSTIC_LINE_INTERVAL == 0:
                    elapsed = time.perf_counter() - scan_started
                    logger.info(
                        "TTL diagnostic: scanning line=%d approx_chars=%d "
                        "elapsed_seconds=%.3f approx_mib_per_second=%.2f",
                        line_number,
                        characters_processed,
                        elapsed,
                        (characters_processed / 1_048_576) / elapsed,
                    )
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                snippet = _bounded_snippet(stripped)
                if len(stripped) > MAX_SNIPPET_LENGTH:
                    truncated_lines += 1

                prefix_match = PREFIX_PATTERN.match(stripped)
                if prefix_match:
                    prefix = prefix_match.group(1) or prefix_match.group(3) or ""
                    namespace = prefix_match.group(2) or prefix_match.group(4)
                    if len(prefixes) < MAX_PREFIXES:
                        prefixes[prefix] = namespace
                    if len(namespaces) < MAX_NAMESPACES:
                        namespaces.add(namespace)

                subject_match = SUBJECT_PATTERN.match(stripped)
                if subject_match:
                    definition_count += 1
                    if len(definition_examples) < MAX_DEFINITION_EXAMPLES:
                        definition_examples.append(
                            {
                                "source_file": path.name,
                                "line": line_number,
                                "subject": subject_match.group(1),
                                "type": _bounded_snippet(subject_match.group(2)),
                            }
                        )

                lowered = stripped.lower()
                matched_categories = [
                    category
                    for category, terms in CATEGORY_TERMS.items()
                    if any(term in lowered for term in terms)
                ]
                for category in matched_categories:
                    categories[category] += 1

                matched_keywords = sorted(
                    keyword for keyword in defect_keywords if keyword in lowered
                )
                for keyword in matched_keywords:
                    relevant_keyword_counts[keyword] += 1

                if matched_keywords or matched_categories:
                    score = len(matched_keywords) * 10 + len(matched_categories)
                    reason_parts = []
                    if matched_keywords:
                        reason_parts.append(
                            "Matches defect keyword(s): " + ", ".join(matched_keywords)
                        )
                    if matched_categories:
                        reason_parts.append(
                            "Relevant TTL category: " + ", ".join(matched_categories)
                        )
                    match = {
                        "source_file": path.name,
                        "line": line_number,
                        "match": snippet,
                        "reason": "; ".join(reason_parts),
                        "score": score,
                    }
                    sequence += 1
                    _push_bounded(relevant_heap, score, sequence, match)

        logger.info(
            "TTL diagnostic: stream exhausted lines=%d approx_chars=%d; "
            "ranking %d retained matches",
            line_count,
            characters_processed,
            len(relevant_heap),
        )
        relevant_matches = [
            item[2]
            for item in sorted(relevant_heap, key=lambda item: (-item[0], item[1]))
        ]
        logger.info("TTL diagnostic: ranking complete; building bounded evidence")
        return {
            "source_file": path.name,
            "file_path": str(path.resolve()),
            "file_size_bytes": path.stat().st_size,
            "line_count": line_count,
            "prefix_count": len(prefixes),
            "prefixes": prefixes,
            "namespaces": sorted(namespaces),
            "definition_count": definition_count,
            "definition_counts_by_category": dict(categories),
            "selected_definitions": definition_examples,
            "defect_keywords": sorted(defect_keywords),
            "relevant_keyword_counts": dict(
                relevant_keyword_counts.most_common(MAX_KEYWORDS)
            ),
            "relevant_matches": relevant_matches,
            "truncated_source_lines": truncated_lines,
            "analysis_limits": {
                "prefixes": MAX_PREFIXES,
                "namespaces": MAX_NAMESPACES,
                "selected_definitions": MAX_DEFINITION_EXAMPLES,
                "relevant_matches": MAX_RELEVANT_MATCHES,
                "snippet_characters": MAX_SNIPPET_LENGTH,
            },
            "full_file_content_returned": False,
        }


def _defect_keywords(description: str) -> set[str]:
    stop_words = {
        "after", "before", "from", "have", "into", "that", "the", "this",
        "was", "were", "what", "when", "with", "without",
    }
    user_terms = {
        token.lower()
        for token in TOKEN_PATTERN.findall(description)
        if token.lower() not in stop_words
    }
    domain_terms = {
        term
        for terms in CATEGORY_TERMS.values()
        for term in terms
        if term in description.lower()
    }
    return user_terms | domain_terms


def _bounded_snippet(text: str) -> str:
    if len(text) <= MAX_SNIPPET_LENGTH:
        return text
    return text[: MAX_SNIPPET_LENGTH - 3] + "..."


def _push_bounded(
    heap: list[tuple[int, int, dict[str, Any]]],
    score: int,
    sequence: int,
    match: dict[str, Any],
) -> None:
    item = (score, sequence, match)
    if len(heap) < MAX_RELEVANT_MATCHES:
        heapq.heappush(heap, item)
    elif score > heap[0][0]:
        heapq.heapreplace(heap, item)