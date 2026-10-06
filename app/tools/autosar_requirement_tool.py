"""Bounded AUTOSAR requirement lookup through official AUTOSAR search pages."""

from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import re
import ssl
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode, urljoin, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

import certifi
import truststore

from app.orchestrator.cancellation import AnalysisCancelledError
from app.orchestrator.evidence import Evidence
from app.tools.base import AnalysisTool
from input.models import AnalysisRequest

logger = logging.getLogger(__name__)

AUTOSAR_REQUIREMENT_ANALYSIS = 120
AUTOSAR_BASE_URL = "https://www.autosar.org"
DEFAULT_AUTOSAR_RELEASE = "R25-11"
AUTOSAR_RELEASE_PATTERN = re.compile(r"\bR\d{2}-\d{2}\b", re.IGNORECASE)
REQUIREMENT_ID_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])\[(?P<id>(?:SWS|RS|SRS|PRS|TPS|ASWS)_[A-Za-z0-9][A-Za-z0-9_]{2,})\](?![A-Za-z0-9_])"
)
TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_/-]{1,}")
MAX_SEARCH_QUERIES = 3
MAX_SEARCH_PAGE_BYTES = 1_000_000
MAX_PDF_BYTES = 12 * 1024 * 1024
MAX_PDF_PAGES = 400
MAX_PAGE_TEXT_CHARACTERS = 40_000
MAX_DOCUMENTS_TO_READ = 3
MAX_REQUIREMENTS_RETURNED = 5
MAX_REQUIREMENT_EXCERPT_CHARACTERS = 220
MAX_CACHE_ENTRIES = 100
MAX_CACHE_FILE_BYTES = 512_000
CACHE_TTL_SECONDS = 30 * 24 * 60 * 60
AUTOSAR_CACHE_VERSION = 2
HTTP_TIMEOUT_SECONDS = 10
MIN_REQUEST_INTERVAL_SECONDS = 1.0

_REQUEST_LOCK = threading.Lock()
_LAST_REQUEST_AT = 0.0

_CONCEPT_QUERIES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (
        "E2E protection",
        ("e2e", "end-to-end", "crc", "sequence counter"),
        "E2E protection counter timeout data validity requirements",
    ),
    (
        "SOME/IP service discovery",
        ("someip-sd", "some/ip-sd", "service discovery", "subscription", "offer service"),
        "SOME/IP service discovery offer subscription requirements",
    ),
    (
        "SOME/IP communication",
        ("someip", "some/ip", "service id", "method id", "event group"),
        "SOME/IP communication message service requirements",
    ),
    (
        "diagnostics",
        ("dem", "dtc", "dcm", "diagnostic", "debounce", "event status"),
        "diagnostic event DTC status debounce requirements",
    ),
    (
        "communication signal validity",
        (
            "unavailable", "invalid", "timeout", "signal", "sensorstatus",
            "functionstatus", "pdu", "communication", "timeout counter",
        ),
        "AUTOSAR COM communication signal invalidation reception timeout requirements",
    ),
    (
        "CAN communication",
        ("can-fd", "canfd", "can", "can bus", "frame"),
        "CAN CAN-FD communication PDU reception requirements",
    ),
    (
        "Ethernet communication",
        ("ethernet", "udp", "tcp", "soad", "tcpip"),
        "Ethernet TCP UDP communication requirements",
    ),
    (
        "network management",
        ("network management", "nm", "bus sleep", "network state"),
        "AUTOSAR Network Management state timeout requirements",
    ),
    (
        "RTE and software component data",
        ("rte", "software component", "data element", "functionstatus", "sensorstatus"),
        "RTE data element invalidation data status requirements",
    ),
    (
        "ECU state management",
        ("ecu state manager", "ecum", "kl15", "ignition", "ecu state"),
        "ECU State Manager operating state requirements",
    ),
)

_MODULE_TERMS = {
    "e2e", "someip", "can", "canfd", "ethernet", "com", "dem", "dcm",
    "pdur", "soad", "tcpip", "nvm", "rte", "ecum", "nm", "bsw",
}
_BEHAVIOR_TERMS = {
    "timeout", "delayed", "loss", "lost", "unavailable", "invalid",
    "counter", "sequence", "debounce", "detection", "status", "drop",
    "reception", "invalidation", "crc", "late", "expired", "signal",
}

class _SearchLinkParser(HTMLParser):
    """Collect anchors from a bounded official search response."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: Optional[str] = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "a":
            return
        self._href = dict(attrs).get("href")
        self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, " ".join(self._text)))
            self._href = None
            self._text = []


class _OfficialRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved_url = urljoin(req.full_url, newurl)
        if not is_official_autosar_url(resolved_url):
            raise URLError("AUTOSAR redirected outside the official domain.")
        return super().redirect_request(req, fp, code, msg, headers, resolved_url)


class AutosarMetadataCache:
    """Small cache for query/document identifiers and short extracted excerpts."""

    def __init__(self, root: Path | None = None) -> None:
        self._explicit_root = root

    @property
    def root(self) -> Path:
        configured = os.getenv("AUTOSAR_CACHE_DIR")
        if configured:
            return Path(configured)
        return self._explicit_root or (
            Path(__file__).resolve().parents[2] / ".cache" / "autosar"
        )

    @property
    def path(self) -> Path:
        return self.root / "requirements.json"

    @staticmethod
    def key(query: str, release: str, document_id: str, source_url: str) -> str:
        value = "\n".join(
            (str(AUTOSAR_CACHE_VERSION), query, release, document_id, source_url)
        )
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def get(
        self, query: str, release: str, document_id: str, source_url: str
    ) -> Optional[list[dict[str, Any]]]:
        data = self._read()
        entry = data.get(
            self.key(query, release, document_id, source_url)
        )
        if not isinstance(entry, dict):
            return None
        if entry.get("cache_version") != AUTOSAR_CACHE_VERSION:
            return None
        if entry.get("query") != query or entry.get("release") != release:
            return None
        if entry.get("document_id") != document_id or entry.get("source_url") != source_url:
            return None
        if not is_official_document_url(source_url, release):
            return None
        try:
            age = time.time() - float(entry.get("updated_at", 0))
        except (TypeError, ValueError):
            return None
        requirements = entry.get("requirements")
        if age < 0 or age > CACHE_TTL_SECONDS or not isinstance(requirements, list):
            return None
        verified = []
        for item in requirements:
            if not isinstance(item, dict):
                continue
            requirement_id = item.get("requirement_id")
            if (
                item.get("release") == release
                and item.get("document_id") == document_id
                and item.get("source_url") == source_url
                and isinstance(requirement_id, str)
                and REQUIREMENT_ID_PATTERN.fullmatch(f"[{requirement_id}]")
                and isinstance(item.get("requirement_summary"), str)
                and len(item["requirement_summary"]) <= MAX_REQUIREMENT_EXCERPT_CHARACTERS
            ):
                verified.append(item)
        return verified[:MAX_REQUIREMENTS_RETURNED]

    def put(
        self,
        query: str,
        release: str,
        document_id: str,
        source_url: str,
        requirements: list[dict[str, Any]],
    ) -> None:
        if not is_official_document_url(source_url, release):
            return
        data = self._read()
        key = self.key(query, release, document_id, source_url)
        data[key] = {
            "cache_version": AUTOSAR_CACHE_VERSION,
            "query": query[:200],
            "release": release,
            "document_id": document_id[:160],
            "source_url": source_url[:500],
            "updated_at": time.time(),
            "requirements": [
                _bounded_requirement(item) for item in requirements[:MAX_REQUIREMENTS_RETURNED]
            ],
        }
        if len(data) > MAX_CACHE_ENTRIES:
            data = dict(
                sorted(
                    data.items(),
                    key=lambda pair: _cache_timestamp(pair[1]),
                    reverse=True,
                )[:MAX_CACHE_ENTRIES]
            )
        encoded = json.dumps(data, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_CACHE_FILE_BYTES:
            return
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".json.tmp")
            if self.path.is_symlink() or temporary.is_symlink():
                return
            temporary.write_text(encoded, encoding="utf-8")
            temporary.replace(self.path)
        except OSError:
            logger.warning("AUTOSAR metadata cache could not be written.")

    def _read(self) -> dict[str, Any]:
        try:
            if self.path.is_symlink():
                return {}
            if self.path.stat().st_size > MAX_CACHE_FILE_BYTES:
                return {}
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, RuntimeError, json.JSONDecodeError):
            return {}
        if not isinstance(value, dict):
            return {}
        return {
            key: entry
            for key, entry in value.items()
            if isinstance(key, str) and isinstance(entry, dict)
        }


class AUTOSARRequirementTool(AnalysisTool):
    """Search public AUTOSAR release pages and inspect a few official PDFs."""

    name = "AUTOSAR Requirement Analysis"
    phase = AUTOSAR_REQUIREMENT_ANALYSIS

    def __init__(
        self,
        *,
        cache: AutosarMetadataCache | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.cache = cache or AutosarMetadataCache()
        configured_timeout = timeout_seconds or _positive_float(
            os.getenv("AUTOSAR_HTTP_TIMEOUT_SECONDS"), HTTP_TIMEOUT_SECONDS
        )
        self.timeout_seconds = min(max(configured_timeout, 1.0), 20.0)
        self._cancelled = False

    def is_applicable(self, request: AnalysisRequest) -> bool:
        return bool(request.defect_description.strip())

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
        release, release_source = select_autosar_release(request, prior)
        platform_preference = select_autosar_platform(request, prior)
        queries = generate_targeted_queries(request, prior)
        if not queries:
            return self._no_match_evidence(release, release_source, [], 0)
        if os.getenv("AUTOSAR_OFFLINE", "").strip().lower() in {"1", "true", "yes", "on"}:
            return self._unavailable_evidence(
                release, release_source, queries, ["offline_mode"], 0
            )

        self._report(on_progress, f"Searching official AUTOSAR sources for {release}...")
        documents: dict[str, dict[str, Any]] = {}
        failures: list[str] = []
        completed_searches = 0
        for query in queries:
            self._check_cancelled()
            try:
                links = self._search_official(query, release)
                completed_searches += 1
            except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
                failures.append(_failure_kind(error))
                continue
            ranked = sorted(
                links,
                key=lambda item: _document_score(item, query, platform_preference),
                reverse=True,
            )
            for document in ranked[:2]:
                self._check_cancelled()
                document["query"] = query
                document["document_score"] = _document_score(
                    document, query, platform_preference
                )
                existing = documents.get(document["source_url"])
                if (
                    existing is None
                    or document["document_score"] > existing["document_score"]
                ):
                    documents[document["source_url"]] = document

        if not documents:
            if failures:
                return self._unavailable_evidence(
                    release, release_source, queries, failures, completed_searches
                )
            return self._no_match_evidence(
                release, release_source, queries, completed_searches
            )

        candidates: list[dict[str, Any]] = []
        documents_inspected = 0
        for document in sorted(
            documents.values(),
            key=lambda item: item["document_score"],
            reverse=True,
        )[:MAX_DOCUMENTS_TO_READ]:
            self._check_cancelled()
            documents_inspected += 1
            document["release"] = release
            query = document["query"]
            document_id = document["document_id"]
            source_url = document["source_url"]
            cached = self.cache.get(query, release, document_id, source_url)
            if cached is not None:
                for cached_item in cached:
                    excerpt = cached_item.get("requirement_summary")
                    if not isinstance(excerpt, str):
                        continue
                    refreshed = extract_requirement_candidates(
                        [excerpt], document, query, prior
                    )
                    for candidate in refreshed:
                        candidate["source_page"] = cached_item.get("source_page")
                    candidates.extend(refreshed)
                continue
            try:
                pdf_bytes = self._fetch_pdf(source_url, release)
                page_texts = _extract_pdf_pages(pdf_bytes)
            except Exception as error:  # noqa: BLE001 - malformed PDFs must not abort analysis
                failures.append(_failure_kind(error))
                continue
            extracted = extract_requirement_candidates(
                page_texts,
                document,
                query,
                prior,
            )
            self.cache.put(query, release, document_id, source_url, extracted)
            candidates.extend(extracted)

        if len(documents) > documents_inspected:
            failures.append("document_scan_limit_reached")

        ranked_candidates = rank_requirement_candidates(candidates)
        relevant = [
            item for item in ranked_candidates
            if float(item.get("confidence", 0.0)) >= 0.25
        ][:MAX_REQUIREMENTS_RETURNED]
        if relevant:
            status = "matched"
            summary = (
                f"Retrieved {len(relevant)} relevant requirement candidate(s) from "
                f"official AUTOSAR {release} documents. Applicability remains evidence-based."
            )
            if failures:
                summary += " Some official searches or documents could not be inspected."
            severity = "info"
        elif failures:
            return self._unavailable_evidence(
                release, release_source, queries, failures, completed_searches,
                documents_searched=documents_inspected,
            )
        else:
            status = "no_match"
            summary = "No matching AUTOSAR requirement identified"
            severity = "warning"

        return Evidence(
            source="AUTOSAR Official Specification",
            summary=summary,
            details={
                "status": status,
                "release": release,
                "release_source": release_source,
                "platform_preference": platform_preference,
                "platform": _platform_label(relevant[0]["platform"]) if relevant else None,
                "queries": queries,
                "requirements": relevant,
                "documents_searched": documents_inspected,
                "documents_selected": len(documents),
                "official_searches_completed": completed_searches,
                "lookup_complete": not failures,
                "failure_categories": sorted(set(failures)),
                "source_url": AUTOSAR_BASE_URL,
                "evidence_found": bool(relevant),
                "limits": {
                    "max_queries": MAX_SEARCH_QUERIES,
                    "max_documents_read": MAX_DOCUMENTS_TO_READ,
                    "max_requirements": MAX_REQUIREMENTS_RETURNED,
                    "max_excerpt_characters": MAX_REQUIREMENT_EXCERPT_CHARACTERS,
                    "pdfs_cached": False,
                },
            },
            severity=severity,
        )

    def _search_official(self, query: str, release: str) -> list[dict[str, str]]:
        params = urlencode(
            [
                ("tx_solr[filter][0]", f"category:{release}"),
                ("tx_solr[q]", query),
            ]
        )
        url = f"{AUTOSAR_BASE_URL}/search?{params}"
        if not _is_official_search_url(url):
            raise ValueError("Invalid official AUTOSAR search URL.")
        payload = self._fetch(url, MAX_SEARCH_PAGE_BYTES, "text/html")
        page_text = payload.decode("utf-8", errors="replace")
        if "autosar documents" not in page_text.casefold() and "documents found" not in page_text.casefold():
            raise ValueError("AUTOSAR search returned an unrecognized page.")
        parser = _SearchLinkParser()
        parser.feed(page_text)
        documents: dict[str, dict[str, str]] = {}
        for href, title in parser.links:
            source_url = urljoin(AUTOSAR_BASE_URL, html.unescape(href))
            if not is_official_document_url(source_url, release):
                continue
            document_id = Path(urlsplit(source_url).path).stem
            if not document_id.startswith("AUTOSAR_"):
                continue
            normalized_title = _normalize_text(title)[:180]
            if not normalized_title:
                normalized_title = document_id.replace("_", " ")
            documents[source_url] = {
                "document": normalized_title,
                "document_id": document_id,
                "source_url": source_url,
                "platform": _platform_from_document(document_id),
            }
        return list(documents.values())

    def _fetch_pdf(self, url: str, release: str) -> bytes:
        if not is_official_document_url(url, release):
            raise ValueError("Rejected a non-official AUTOSAR document URL.")
        return self._fetch(url, MAX_PDF_BYTES, "application/pdf")

    def _fetch(self, url: str, max_bytes: int, accept: str) -> bytes:
        _rate_limit()
        request = Request(
            url,
            headers={
                "User-Agent": "TraceTitansLogAnalyserAgent/1.0 (AUTOSAR public search)",
                "Accept": accept,
            },
        )
        try:
            tls_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except Exception:  # noqa: BLE001 - verified certifi fallback only
            tls_context = ssl.create_default_context(cafile=certifi.where())
        opener = build_opener(
            _OfficialRedirectHandler(), HTTPSHandler(context=tls_context)
        )
        with opener.open(request, timeout=self.timeout_seconds) as response:
            final_url = response.geturl()
            if not is_official_autosar_url(final_url):
                raise ValueError("AUTOSAR response left the official domain.")
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise ValueError("AUTOSAR response exceeded the size limit.")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold()
            expected_type = "application/pdf" if accept == "application/pdf" else "text/html"
            if content_type and content_type != expected_type:
                raise ValueError("AUTOSAR response had an unexpected content type.")
            payload = response.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise ValueError("AUTOSAR response exceeded the size limit.")
        return payload

    def _no_match_evidence(
        self, release: str, release_source: str, queries: list[str], completed: int
    ) -> Evidence:
        return Evidence(
            source="AUTOSAR Official Specification",
            summary="No matching AUTOSAR requirement identified",
            details={
                "status": "no_match",
                "release": release,
                "release_source": release_source,
                "queries": queries,
                "requirements": [],
                "documents_searched": 0,
                "official_searches_completed": completed,
                "lookup_complete": True,
                "source_url": AUTOSAR_BASE_URL,
                "evidence_found": False,
                "limits": {"max_queries": MAX_SEARCH_QUERIES, "max_excerpt_characters": MAX_REQUIREMENT_EXCERPT_CHARACTERS},
            },
            severity="warning",
        )

    def _unavailable_evidence(
        self,
        release: str,
        release_source: str,
        queries: list[str],
        failures: list[str],
        completed: int,
        documents_searched: int = 0,
    ) -> Evidence:
        return Evidence(
            source="AUTOSAR Official Specification",
            summary="Official AUTOSAR lookup could not be completed.",
            details={
                "status": "unavailable",
                "release": release,
                "release_source": release_source,
                "queries": queries,
                "requirements": [],
                "documents_searched": documents_searched,
                "official_searches_completed": completed,
                "lookup_complete": False,
                "failure_categories": sorted(set(failures)),
                "source_url": AUTOSAR_BASE_URL,
                "evidence_found": False,
                "limits": {"max_queries": MAX_SEARCH_QUERIES, "max_excerpt_characters": MAX_REQUIREMENT_EXCERPT_CHARACTERS},
            },
            severity="warning",
        )

    def _check_cancelled(self) -> None:
        if self._cancelled:
            raise AnalysisCancelledError("Analysis cancelled by the user.")

    @staticmethod
    def _report(callback: Optional[Callable[[str], None]], message: str) -> None:
        if callback:
            callback(message)


def is_official_autosar_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return bool(
            parsed.scheme.lower() == "https"
            and parsed.hostname
            and parsed.hostname.casefold() in {"autosar.org", "www.autosar.org"}
            and parsed.username is None
            and parsed.password is None
            and parsed.port in (None, 443)
        )
    except ValueError:
        return False


def _is_official_search_url(url: str) -> bool:
    return is_official_autosar_url(url) and urlsplit(url).path == "/search"


def is_official_document_url(url: str, release: str) -> bool:
    if not is_official_autosar_url(url):
        return False
    parsed = urlsplit(url)
    decoded_path = unquote(parsed.path)
    if "\\" in decoded_path or any(
        segment in {".", ".."} for segment in decoded_path.split("/")
    ):
        return False
    expected_prefix = f"/fileadmin/standards/{release}/"
    return (
        parsed.hostname.casefold() == "www.autosar.org"
        and decoded_path.startswith(expected_prefix)
        and decoded_path.lower().endswith(".pdf")
        and not parsed.query
        and not parsed.fragment
    )


def select_autosar_release(
    request: AnalysisRequest, evidence: list[Evidence]
) -> tuple[str, str]:
    repository_text = "\n".join(
        _evidence_text(item)
        for item in evidence
        if item.source.startswith("Repository")
    )
    releases = AUTOSAR_RELEASE_PATTERN.findall(repository_text)
    if releases:
        counts = Counter(item.upper() for item in releases)
        selected = max(
            counts,
            key=lambda item: (counts[item], *_release_numbers(item)),
        )
        return selected, "repository evidence"

    configured = os.getenv("AUTOSAR_RELEASE", "").strip().upper()
    if configured:
        if AUTOSAR_RELEASE_PATTERN.fullmatch(configured):
            return configured, "AUTOSAR_RELEASE configuration"
        logger.warning("Invalid AUTOSAR_RELEASE setting; using current official release.")
    return DEFAULT_AUTOSAR_RELEASE, "current official release"


def select_autosar_platform(
    request: AnalysisRequest, evidence: list[Evidence]
) -> Optional[str]:
    context = request.defect_description + "\n" + "\n".join(
        _evidence_text(item) for item in evidence[:12]
    )
    classic_markers = (
        "classic platform", "bsw", "dem", "dcm", "pdur", "soad", "tcpip",
        "nvm", "ecum", "com", "rte",
    )
    adaptive_markers = (
        "adaptive platform", "ara::com", "execution management", "manifest",
    )
    classic = any(_contains_concept(context, marker) for marker in classic_markers)
    adaptive = any(_contains_concept(context, marker) for marker in adaptive_markers)
    if classic == adaptive:
        return None
    return "CP" if classic else "AP"


def generate_targeted_queries(
    request: AnalysisRequest, evidence: list[Evidence]
) -> list[str]:
    context = "\n".join(
        [request.defect_description[:2_000]]
        + [_evidence_text(item) for item in evidence[:12]]
    )[:12_000].casefold()
    queries = []
    for _, triggers, query in _CONCEPT_QUERIES:
        if any(_contains_concept(context, trigger) for trigger in triggers):
            queries.append(query)
        if len(queries) >= MAX_SEARCH_QUERIES:
            break
    if not queries:
        known_modules = [
            name for name in ("COM", "PduR", "SoAd", "TcpIp", "DEM", "DCM", "RTE", "BSW", "NvM")
            if re.search(rf"\b{re.escape(name)}\b", context, re.IGNORECASE)
        ]
        subject = " ".join(known_modules[:3]) or "communication data availability"
        queries.append(f"AUTOSAR {subject} functional requirements")
    return queries[:MAX_SEARCH_QUERIES]


def extract_requirement_candidates(
    page_texts: list[str],
    document: dict[str, Any],
    query: str,
    evidence: list[Evidence],
) -> list[dict[str, Any]]:
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    evidence_text = "\n".join(_evidence_text(item) for item in evidence[:12]).casefold()
    query_tokens = _meaningful_tokens(query)
    document_tokens = _meaningful_tokens(document.get("document", ""))
    for page_number, page_text in enumerate(page_texts, start=1):
        if not page_text:
            continue
        requirement_matches = list(REQUIREMENT_ID_PATTERN.finditer(page_text))
        for match_index, match in enumerate(requirement_matches):
            requirement_id = match.group("id")
            next_start = (
                requirement_matches[match_index + 1].start()
                if match_index + 1 < len(requirement_matches)
                else min(len(page_text), match.end() + 700)
            )
            end = min(next_start, match.end() + 700)
            context = _normalize_text(page_text[match.start():end])
            excerpt = _copyright_safe_excerpt(context, requirement_id)
            if not excerpt:
                continue
            excerpt_tokens = _meaningful_tokens(context)
            overlap = query_tokens.intersection(excerpt_tokens)
            title_overlap = query_tokens.intersection(document_tokens)
            evidence_tokens = _meaningful_tokens(evidence_text)
            evidence_overlap = query_tokens.intersection(evidence_tokens, excerpt_tokens)
            behavior_overlap = (
                query_tokens
                .intersection(evidence_tokens, excerpt_tokens, _BEHAVIOR_TERMS)
            )
            explicit_behavior = _explicit_behavior_match(
                query_tokens, evidence_tokens, context
            )
            module_overlap = query_tokens.intersection(excerpt_tokens, _MODULE_TERMS)
            document_modules = {
                part.casefold()
                for part in str(document["document_id"]).split("_")
            }.intersection(_MODULE_TERMS)
            implementation_module_overlap = document_modules.intersection(evidence_tokens)
            concept_overlap = overlap - _MODULE_TERMS
            obligation = bool(re.search(r"\b(shall|must|is required to)\b", context, re.IGNORECASE))
            query_size = max(len(query_tokens), 1)
            score = min(
                1.0,
                0.10
                + 0.30 * len(overlap) / query_size
                + 0.10 * len(title_overlap) / query_size
                + (0.10 if module_overlap else 0.0)
                + (0.20 if implementation_module_overlap else 0.0)
                + (0.10 if obligation else 0.0)
                + 0.10 * len(evidence_overlap) / query_size
                + (0.20 if behavior_overlap else 0.0),
            )
            applicability = _applicability(
                score,
                bool(module_overlap),
                len(concept_overlap),
                explicit_behavior,
                obligation,
            )
            reasons = []
            if title_overlap:
                reasons.append("official document title matches the targeted concept")
            if implementation_module_overlap:
                reasons.append("official module matches repository/RAG implementation evidence")
            if overlap:
                reasons.append("requirement context contains targeted AUTOSAR terminology")
            if evidence_overlap:
                reasons.append("requirement context overlaps supplied log/repository evidence")
            if explicit_behavior:
                reasons.append("same defect behavior appears in source, query, and supplied evidence")
            if obligation:
                reasons.append("source context uses normative requirement wording")
            candidate = {
                "release": document["release"],
                "platform": document["platform"],
                "document": document["document"],
                "document_id": document["document_id"],
                "requirement_id": requirement_id,
                "requirement_title": _requirement_title(context, requirement_id),
                "requirement_summary": excerpt,
                "source_url": document["source_url"],
                "source_page": page_number,
                "relevance_reason": "; ".join(reasons)[:400],
                "confidence": round(score, 3),
                "applicability": applicability,
                "query": query,
            }
            key = (requirement_id, str(document["document_id"]))
            if key not in candidates or candidate["confidence"] > candidates[key]["confidence"]:
                candidates[key] = candidate
    return sorted(
        candidates.values(), key=lambda item: item["confidence"], reverse=True
    )[:MAX_REQUIREMENTS_RETURNED]


def extract_requirement_ids(text: str) -> list[str]:
    """Return only IDs explicitly present in official-source text."""

    return list(dict.fromkeys(match.group("id") for match in REQUIREMENT_ID_PATTERN.finditer(text)))


def rank_requirement_candidates(
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        (_bounded_requirement(candidate) for candidate in candidates),
        key=lambda item: float(item.get("confidence", 0.0)),
        reverse=True,
    )[:MAX_REQUIREMENTS_RETURNED]


def _extract_pdf_pages(pdf_bytes: bytes) -> list[str]:
    if not pdf_bytes or len(pdf_bytes) > MAX_PDF_BYTES:
        raise ValueError("Official AUTOSAR PDF was empty or exceeded the size limit.")
    try:
        from pypdf import PdfReader
    except ImportError as error:
        raise ImportError("Install the pypdf dependency to inspect official PDFs.") from error
    reader = PdfReader(BytesIO(pdf_bytes), strict=False)
    if len(reader.pages) > MAX_PDF_PAGES:
        raise ValueError("AUTOSAR PDF exceeds the bounded page scan limit.")
    pages: list[str] = []
    for page in reader.pages[:MAX_PDF_PAGES]:
        text = page.extract_text() or ""
        pages.append(text[:MAX_PAGE_TEXT_CHARACTERS])
    return pages


def _document_score(
    document: dict[str, Any], query: str, preferred_platform: Optional[str] = None
) -> float:
    document_id = str(document.get("document_id", ""))
    title_tokens = _meaningful_tokens(
        f"{document.get('document', '')} {document_id.replace('_', ' ')}"
    )
    query_tokens = _meaningful_tokens(query)
    overlap = len(title_tokens.intersection(query_tokens))
    kind_score = 1.5 if "_RS_" in document_id or "_SRS_" in document_id else 0.8
    if "_SWS_" in document_id or "_PRS_" in document_id:
        kind_score = 1.2
    module_tokens = {part.casefold() for part in document_id.split("_")}
    module_score = 2.5 if module_tokens.intersection(query_tokens, _MODULE_TERMS) else 0.0
    platform_score = 1.5 if preferred_platform and document.get("platform") == preferred_platform else 0.0
    return overlap * 2.0 + module_score + platform_score + kind_score


def _applicability(
    score: float,
    module_match: bool,
    concept_overlap: int,
    behavior_match: bool,
    obligation: bool,
) -> str:
    if score >= 0.72 and behavior_match and obligation:
        return "DIRECTLY APPLICABLE"
    if score >= 0.58 and module_match and concept_overlap >= 2:
        return "PARTIALLY APPLICABLE"
    if score >= 0.35:
        return "RELATED"
    return "INSUFFICIENT EVIDENCE"


def _explicit_behavior_match(
    query_tokens: set[str], evidence_tokens: set[str], requirement_context: str
) -> bool:
    shared = query_tokens.intersection(evidence_tokens, _BEHAVIOR_TERMS)
    context = requirement_context.casefold()
    if "timeout" in shared and re.search(
        r"\b(?:timeout detection|detect(?:ion)? of timeouts?|detect(?:ion)? timeouts?|timeout mechanism|(?:signal|reception|receive)[ -]timeouts?)\b",
        context,
    ):
        return True
    if "invalid" in shared and re.search(
        r"\b(?:invalid(?:ation)? (?:data|signal)|(?:data|signal) invalidation)\b",
        context,
    ):
        return True
    if "unavailable" in shared and re.search(r"\bdata availability\b", context):
        return True
    if "counter" in shared and re.search(
        r"\b(?:counter (?:error|failure|validation|delta)|maximum delta counter)\b",
        context,
    ):
        return True
    if "debounce" in shared and "debounce" in context:
        return True
    return False


def _copyright_safe_excerpt(context: str, requirement_id: str) -> str:
    context = _normalize_text(context)
    if requirement_id not in context:
        return ""
    if len(context) <= MAX_REQUIREMENT_EXCERPT_CHARACTERS:
        return context
    identifier_offset = context.index(requirement_id)
    start = identifier_offset
    end = min(len(context), start + MAX_REQUIREMENT_EXCERPT_CHARACTERS)
    excerpt = context[start:end]
    if start:
        excerpt = "..." + excerpt[3:]
    if end < len(context):
        excerpt = excerpt[:-3] + "..."
    return excerpt


def _requirement_title(context: str, requirement_id: str) -> Optional[str]:
    match = re.search(
        r"(?:requirement\s+title|title)\s*:\s*([^.;\n]{3,120})",
        context,
        re.IGNORECASE,
    )
    if match:
        return _normalize_text(match.group(1))[:120]
    return None


def _bounded_requirement(item: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "release", "platform", "document", "document_id", "requirement_id",
        "requirement_title", "requirement_summary", "source_url", "source_page",
        "relevance_reason", "confidence", "applicability", "query",
    )
    bounded = {key: item[key] for key in allowed if key in item}
    for key, limit in (
        ("document", 180), ("document_id", 160), ("requirement_id", 80),
        ("requirement_title", 120), ("requirement_summary", MAX_REQUIREMENT_EXCERPT_CHARACTERS),
        ("source_url", 500), ("relevance_reason", 400), ("query", 200),
    ):
        if isinstance(bounded.get(key), str):
            bounded[key] = bounded[key][:limit]
    if "confidence" in bounded:
        try:
            bounded["confidence"] = round(min(max(float(bounded["confidence"]), 0), 1), 3)
        except (ValueError, TypeError):
            bounded["confidence"] = 0.0
    return bounded


def _evidence_text(item: Evidence) -> str:
    pieces = [item.summary[:1_000]]
    budget = 3_000

    def collect(value: Any) -> None:
        nonlocal budget
        if budget <= 0:
            return
        if isinstance(value, str):
            text = value[: min(600, budget)]
            pieces.append(text)
            budget -= len(text)
        elif isinstance(value, dict):
            for key, child in list(value.items())[:80]:
                if key in {
                    "text", "context", "summary", "service", "signal", "identifier",
                    "value", "matches", "chunks", "search_targets",
                }:
                    collect(child)
                if budget <= 0:
                    return
        elif isinstance(value, list):
            for child in value[:40]:
                collect(child)
                if budget <= 0:
                    return

    collect(item.details)
    return " ".join(pieces)[:4_000]


def _meaningful_tokens(value: str) -> set[str]:
    tokens: set[str] = set()
    for token in TOKEN_PATTERN.findall(value):
        normalized = token.casefold()
        tokens.add(normalized.replace("/", ""))
        tokens.update(part for part in re.split(r"[_/-]+", normalized) if part)
    stop_words = {"shall", "must", "requirement", "requirements", "autosar", "the", "and", "or", "is", "are", "to", "for", "on", "of", "with", "from", "by", "in", "this", "that", "a"}
    return {token for token in tokens if len(token) > 2 and token not in stop_words}


def _contains_concept(text: str, concept: str) -> bool:
    normalized_text = re.sub(r"[_-]+", " ", text.casefold())
    normalized_concept = re.sub(r"[_-]+", " ", concept.casefold()).strip()
    return bool(
        re.search(
            rf"(?<![a-z0-9]){re.escape(normalized_concept)}(?![a-z0-9])",
            normalized_text,
        )
    )


def _normalize_text(value: str) -> str:
    return " ".join(html.unescape(value).replace("\x00", " ").split())


def _platform_from_document(document_id: str) -> str:
    if "_CP_" in document_id:
        return "CP"
    if "_AP_" in document_id:
        return "AP"
    if "_FO_" in document_id:
        return "Foundation"
    return "Unknown"


def _platform_label(platform: str) -> str:
    return {
        "CP": "Classic Platform",
        "AP": "Adaptive Platform",
        "Foundation": "Foundation",
    }.get(platform, "Unknown")


def _release_numbers(release: str) -> tuple[int, int]:
    match = re.fullmatch(r"R(\d{2})-(\d{2})", release.upper())
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def _positive_float(value: Optional[str], default: float) -> float:
    try:
        number = float(value) if value else default
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def _cache_timestamp(entry: dict[str, Any]) -> float:
    try:
        return float(entry.get("updated_at", 0))
    except (TypeError, ValueError):
        return 0.0


def _failure_kind(error: Exception) -> str:
    if isinstance(error, HTTPError):
        return f"http_{error.code}"
    if isinstance(error, (TimeoutError,)) or "timeout" in type(error).__name__.casefold():
        return "timeout"
    if isinstance(error, URLError):
        reason = getattr(error, "reason", None)
        if isinstance(reason, TimeoutError):
            return "timeout"
        return "network_error"
    if isinstance(error, ImportError):
        return "pdf_support_unavailable"
    if type(error).__module__.startswith("pypdf"):
        return "malformed_pdf"
    if isinstance(error, ValueError):
        return "invalid_or_oversized_official_response"
    return "official_source_error"


def _rate_limit() -> None:
    global _LAST_REQUEST_AT
    with _REQUEST_LOCK:
        now = time.monotonic()
        wait_seconds = MIN_REQUEST_INTERVAL_SECONDS - (now - _LAST_REQUEST_AT)
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        _LAST_REQUEST_AT = time.monotonic()