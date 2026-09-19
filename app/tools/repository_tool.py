"""Safe, bounded and deterministic repository investigation."""

from __future__ import annotations

import fnmatch
import logging
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from app.orchestrator.cancellation import AnalysisCancelledError
from app.orchestrator.evidence import Evidence
from app.tools.base import AnalysisTool
from input.models import AnalysisRequest

logger = logging.getLogger(__name__)

MAX_FILES_SCANNED = 5_000
MAX_FILE_SIZE_MB = 10
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
MAX_SEARCH_RESULTS = 30
MAX_MATCHING_FILES = 20
MAX_CONTEXT_LINES = 3
MAX_CONTEXT_CHARS = 2_000
MAX_SEARCH_TARGETS = 12
MAX_IDENTIFIER_VALUES = 8
MAX_VALUES_PER_IDENTIFIER_KEY = 3
MAX_TARGET_LENGTH = 100
TEXT_SAMPLE_BYTES = 8_192

SUPPORTED_EXTENSIONS = {
    ".c", ".h", ".cpp", ".hpp", ".cxx", ".py", ".java", ".cs", ".rs",
    ".arxml", ".xml", ".json", ".yaml", ".yml", ".ini", ".cfg", ".conf",
    ".txt", ".md", ".toml",
}
IGNORED_DIRECTORIES = {
    ".git", ".github", ".vscode", ".idea", "build", "dist", "out", "target",
    "node_modules", "venv", ".venv", "__pycache__", ".cache", "coverage",
    ".coverage", "htmlcov", ".pytest_cache", ".mypy_cache", ".tox", ".nox",
    "vendor", "third_party", "generated", "cmake-build-debug", "cmake-build-release",
}
IGNORED_FILE_PATTERNS = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "credentials*",
    "secrets*", "*.crt", "*.cer", "*.der", "id_rsa*", "id_ed25519*",
)
TECHNICAL_TERMS = (
    "some/ip", "someip", "service", "service_id", "serviceid", "instance_id",
    "instanceid", "method_id", "methodid", "event_id", "eventid", "eventgroup",
    "response", "request", "timeout", "ethernet", "udp", "tcp", "signal",
    "message", "frame", "pdu", "payload", "communication", "error",
)
STOP_WORDS = {
    "after", "before", "could", "description", "does", "from", "have", "into",
    "is", "not", "that", "the", "this", "was", "were", "what", "when", "with",
    "without", "received", "sent", "observed", "expected", "defect", "failure",
    "missing", "issue", "problem", "repository", "log",
}
HEX_PATTERN = re.compile(r"\b0x[0-9a-fA-F]{2,16}\b")
WORD_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_/-]{2,}")
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)([\"']?\b(?:api[_-]?key|token|password|passwd|secret|authorization)\b[\"']?)"
    r"(\s*[:=]\s*)([^\s,;]+|\"[^\"]*\"|'[^']*')"
)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE)


class RepositoryAnalysisError(RuntimeError):
    """Controlled repository analysis error."""


class RepositorySecurityError(RepositoryAnalysisError):
    """Requested path violates the repository security boundary."""


class RepositoryTool(AnalysisTool):
    """Search a repository once using bounded targets derived from current evidence."""

    name = "Repository Analysis"
    phase = 100

    def __init__(self) -> None:
        self._cancelled = False

    def is_applicable(self, request: AnalysisRequest) -> bool:
        path = Path(request.repo_path)
        return path.exists() and path.is_dir()

    def cancel(self) -> None:
        self._cancelled = True

    def run(
        self,
        request: AnalysisRequest,
        on_progress: Optional[Callable[[str], None]] = None,
        prior_evidence: Optional[list[Evidence]] = None,
    ) -> Evidence:
        self._cancelled = False
        root = _repository_root(request.repo_path)
        targets = derive_search_targets(
            request.defect_description, prior_evidence or []
        )
        _report(on_progress, "Investigating repository...")
        _report(
            on_progress,
            f"Searching repository for {len(targets)} relevant identifiers...",
        )

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
        files = discover_repository_files(root, excluded_paths=excluded_paths)
        matches, files_scanned, inaccessible_files = _search_targets_once(
            root,
            files,
            targets,
            self._check_cancelled,
        )

        for match in matches:
            start_line = max(1, match["line"] - MAX_CONTEXT_LINES)
            end_line = match["line"] + MAX_CONTEXT_LINES
            try:
                match["context"] = read_file(
                    root, match["file"], start_line, end_line
                )["content"]
            except RepositoryAnalysisError as error:
                match["context"] = ""
                match["context_error"] = str(error)

        details = {
            "repository_name": root.name,
            "search_targets": targets,
            "files_discovered": len(files),
            "files_scanned": files_scanned,
            "inaccessible_files": inaccessible_files,
            "matches_found": len(matches),
            "matching_files": len({match["file"] for match in matches}),
            "matches": matches,
            "limits": {
                "max_files_scanned": MAX_FILES_SCANNED,
                "max_file_size_mb": MAX_FILE_SIZE_MB,
                "max_search_results": MAX_SEARCH_RESULTS,
                "max_matching_files": MAX_MATCHING_FILES,
                "max_context_lines": MAX_CONTEXT_LINES,
                "max_context_chars": MAX_CONTEXT_CHARS,
                "max_search_targets": MAX_SEARCH_TARGETS,
            },
            "evidence_found": bool(matches),
            "repository_content_complete": False,
        }
        logger.info(
            "Repository analysis complete: targets=%d files_discovered=%d "
            "files_scanned=%d matches=%d evidence_items=%d",
            len(targets),
            len(files),
            files_scanned,
            len(matches),
            1,
        )
        summary = (
            f"Repository investigation scanned {files_scanned} bounded text files "
            f"for {len(targets)} targets and found {len(matches)} relevant matches "
            f"across {details['matching_files']} files."
        )
        return Evidence(
            source="Repository Analysis",
            summary=summary,
            details=details,
            severity="info",
        )

    def _check_cancelled(self) -> None:
        if self._cancelled:
            raise AnalysisCancelledError("Analysis cancelled by the user.")

    def search_repository(
        self,
        repo_path: str | Path,
        query: str,
        max_results: int = MAX_SEARCH_RESULTS,
    ) -> list[dict[str, Any]]:
        root = _repository_root(repo_path)
        files = discover_repository_files(root)
        matches, _, _ = _search_targets_once(
            root,
            files,
            [query],
            self._check_cancelled,
            max_results=min(max_results, MAX_SEARCH_RESULTS),
        )
        return matches

    def read_file(
        self,
        repo_path: str | Path,
        path: str | Path,
        start_line: int,
        end_line: int,
    ) -> dict[str, Any]:
        return read_file(repo_path, path, start_line, end_line)

    def find_symbol(
        self, repo_path: str | Path, symbol: str
    ) -> list[dict[str, Any]]:
        return self.search_repository(repo_path, symbol)

    def find_configuration(
        self, repo_path: str | Path, key: str
    ) -> list[dict[str, Any]]:
        return self.search_repository(repo_path, key)


def derive_search_targets(
    defect_description: str,
    evidence: list[Evidence],
) -> list[str]:
    """Derive a small ordered target list, prioritizing evidence identifiers."""

    targets: list[str] = []
    evidence_strings = list(_bounded_strings_from_evidence(evidence))
    combined_evidence = "\n".join(evidence_strings)

    technical_key_values = _technical_key_values(evidence, defect_description)
    for _, value in technical_key_values[:MAX_IDENTIFIER_VALUES]:
        _add_target(targets, value)
    for key, _ in technical_key_values:
        _add_target(targets, key)

    for identifier in HEX_PATTERN.findall(combined_evidence):
        _add_target(targets, identifier)

    defect_lower = defect_description.lower()
    evidence_lower = combined_evidence.lower()
    for term in TECHNICAL_TERMS:
        if term in defect_lower or term in evidence_lower:
            _add_target(targets, term)

    for word in WORD_PATTERN.findall(defect_description):
        normalized = word.lower()
        if normalized not in STOP_WORDS:
            _add_target(targets, word)

    return targets[:MAX_SEARCH_TARGETS]


def discover_repository_files(
    repo_path: str | Path,
    *,
    excluded_paths: Optional[set[Path]] = None,
) -> list[Path]:
    root = _repository_root(repo_path)
    excluded_paths = excluded_paths or set()
    discovered: list[Path] = []

    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name.lower() not in IGNORED_DIRECTORIES
            and _safe_inside(root, current / name)
        )
        for file_name in sorted(file_names):
            if len(discovered) >= MAX_FILES_SCANNED:
                return discovered
            if _ignored_file(file_name):
                continue
            candidate = current / file_name
            try:
                resolved = candidate.resolve(strict=True)
                if resolved in excluded_paths or not resolved.is_relative_to(root):
                    continue
                if not resolved.is_file() or resolved.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
                if _looks_textual(resolved):
                    discovered.append(resolved)
            except (OSError, RuntimeError):
                continue
    return discovered


def search_repository(
    repo_path: str | Path,
    query: str,
    max_results: int = MAX_SEARCH_RESULTS,
) -> list[dict[str, Any]]:
    return RepositoryTool().search_repository(repo_path, query, max_results)


def read_file(
    repo_path: str | Path,
    path: str | Path,
    start_line: int,
    end_line: int,
) -> dict[str, Any]:
    root = _repository_root(repo_path)
    candidate = Path(path)
    if candidate.is_absolute():
        raise RepositorySecurityError("Absolute paths are not allowed.")
    if start_line < 1 or end_line < start_line:
        raise RepositoryAnalysisError("Invalid line range.")
    if end_line - start_line + 1 > (MAX_CONTEXT_LINES * 2 + 1):
        raise RepositoryAnalysisError("Requested line range exceeds the context limit.")

    try:
        resolved = (root / candidate).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RepositoryAnalysisError(f"Unable to resolve repository file: {path}") from error
    if not resolved.is_relative_to(root):
        raise RepositorySecurityError("Requested path is outside the repository root.")
    if _ignored_file(resolved.name):
        raise RepositorySecurityError("Sensitive files cannot be read.")
    if not resolved.is_file():
        raise RepositoryAnalysisError("Requested path is not a file.")
    if resolved.stat().st_size > MAX_FILE_SIZE_BYTES:
        raise RepositoryAnalysisError("File exceeds the repository read size limit.")
    if not _looks_textual(resolved):
        raise RepositoryAnalysisError("Binary files cannot be read as repository evidence.")

    lines: list[str] = []
    total_characters = 0
    with resolved.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, start=1):
            if line_number < start_line:
                continue
            if line_number > end_line:
                break
            redacted = redact_secrets(line.rstrip("\r\n"))
            rendered = f"{line_number}: {redacted}"
            remaining = MAX_CONTEXT_CHARS - total_characters
            if remaining <= 0:
                break
            rendered = rendered[:remaining]
            lines.append(rendered)
            total_characters += len(rendered) + 1

    return {
        "file": resolved.relative_to(root).as_posix(),
        "start_line": start_line,
        "end_line": min(end_line, start_line + len(lines) - 1),
        "content": "\n".join(lines),
        "truncated": total_characters >= MAX_CONTEXT_CHARS,
    }


def redact_secrets(text: str) -> str:
    redacted = SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted>", text
    )
    if PRIVATE_KEY_PATTERN.search(redacted):
        return "<redacted private key material>"
    return redacted


def _search_targets_once(
    root: Path,
    files: list[Path],
    targets: list[str],
    check_cancelled: Callable[[], None],
    *,
    max_results: int = MAX_SEARCH_RESULTS,
) -> tuple[list[dict[str, Any]], int, int]:
    normalized_targets = [(target, target.casefold()) for target in targets if target]
    matches: list[dict[str, Any]] = []
    matching_files: set[str] = set()
    files_scanned = 0
    inaccessible_files = 0

    if not normalized_targets:
        return matches, files_scanned, inaccessible_files

    for path in files:
        check_cancelled()
        if len(matches) >= max_results or len(matching_files) >= MAX_MATCHING_FILES:
            break
        relative_path = path.relative_to(root).as_posix()
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                files_scanned += 1
                for line_number, line in enumerate(stream, start=1):
                    if line_number % 1_000 == 0:
                        check_cancelled()
                    lowered = line.casefold()
                    matched_targets = [
                        original
                        for original, normalized in normalized_targets
                        if normalized in lowered
                    ]
                    if not matched_targets:
                        continue
                    matches.append(
                        {
                            "queries": matched_targets[:MAX_SEARCH_TARGETS],
                            "file": relative_path,
                            "line": line_number,
                            "match": redact_secrets(line.strip())[:MAX_CONTEXT_CHARS],
                            "reason": "Matches repository search target(s): "
                            + ", ".join(matched_targets[:MAX_SEARCH_TARGETS]),
                        }
                    )
                    matching_files.add(relative_path)
                    if len(matches) >= max_results:
                        break
        except (OSError, UnicodeError):
            inaccessible_files += 1
    return matches, files_scanned, inaccessible_files


def _repository_root(repo_path: str | Path) -> Path:
    try:
        root = Path(repo_path).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RepositoryAnalysisError(
            f"Repository path does not exist: {repo_path}"
        ) from error
    if not root.is_dir():
        raise RepositoryAnalysisError(f"Repository path is not a directory: {root}")
    return root


def _safe_inside(root: Path, candidate: Path) -> bool:
    try:
        return candidate.resolve(strict=False).is_relative_to(root)
    except (OSError, RuntimeError):
        return False


def _ignored_file(file_name: str) -> bool:
    lowered = file_name.lower()
    return any(fnmatch.fnmatch(lowered, pattern) for pattern in IGNORED_FILE_PATTERNS)


def _looks_textual(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            sample = stream.read(TEXT_SAMPLE_BYTES)
    except OSError:
        return False
    if b"\x00" in sample:
        return False
    if not sample:
        return True
    control_count = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return control_count / len(sample) <= 0.01


def _bounded_strings_from_evidence(evidence: list[Evidence]) -> Iterable[str]:
    remaining = 2_000
    skipped_keys = {
        "file_path", "source_file", "analysis_scope", "tshark_warnings",
        "payload_sample_hex", "record_examples",
    }

    def walk(value: Any) -> Iterable[str]:
        nonlocal remaining
        if remaining <= 0:
            return
        if isinstance(value, str):
            remaining -= 1
            yield value[:500]
        elif isinstance(value, dict):
            for key, item in value.items():
                if remaining <= 0:
                    break
                if str(key).lower() in skipped_keys:
                    continue
                remaining -= 1
                yield str(key)[:100]
                yield from walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value[:100]:
                yield from walk(item)

    for item in evidence:
        yield item.source
        yield item.summary
        yield from walk(item.details)


def _technical_key_values(
    evidence: list[Evidence], defect_description: str
) -> list[tuple[str, str]]:
    ranked_results: list[tuple[int, int, str, str]] = []
    key_scores = {
        "serviceid": 100,
        "instanceid": 95,
        "methodid": 90,
        "eventid": 85,
        "eventgroupid": 85,
        "requestid": 80,
        "sessionid": 78,
        "clientid": 76,
        "messageid": 74,
        "canid": 50,
    }
    configuration_keys = ("timeout", "ecuname", "applicationname")
    defect_lower = defect_description.lower()
    can_relevant = "can" in defect_lower
    sequence = 0

    remaining_nodes = 5_000

    def walk(value: Any) -> None:
        nonlocal remaining_nodes
        nonlocal sequence
        if remaining_nodes <= 0:
            return
        remaining_nodes -= 1
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = str(key).lower()
                normalized_key = re.sub(r"[^a-z0-9]", "", key_text)
                matched_identifier = next(
                    (term for term in key_scores if term in normalized_key), None
                )
                is_configuration = any(
                    term in normalized_key for term in configuration_keys
                )
                if (matched_identifier or is_configuration) and isinstance(item, (str, int)):
                    item_text = str(item)
                    if 1 < len(item_text) <= MAX_TARGET_LENGTH:
                        score = key_scores.get(matched_identifier or "", 60)
                        if matched_identifier == "canid" and not can_relevant:
                            score = 25
                        if matched_identifier == "canid" and item_text.isdigit():
                            item_text = f"0x{int(item_text):X}"
                        ranked_results.append((score, sequence, str(key), item_text))
                        sequence += 1
                walk(item)
        elif isinstance(value, list):
            for item in value[:100]:
                walk(item)

    for evidence_item in evidence:
        walk(evidence_item.details)
    ranked_results.sort(key=lambda item: (-item[0], item[1]))
    deduplicated: list[tuple[str, str]] = []
    seen_values: set[str] = set()
    values_per_key: Counter[str] = Counter()
    for _, _, key, value in ranked_results:
        normalized_value = value.casefold()
        alias = _search_key_alias(key)
        if (
            normalized_value in seen_values
            or values_per_key[alias] >= MAX_VALUES_PER_IDENTIFIER_KEY
        ):
            continue
        deduplicated.append((alias, value))
        seen_values.add(normalized_value)
        values_per_key[alias] += 1
        if len(deduplicated) >= MAX_SEARCH_TARGETS:
            break
    return deduplicated


def _search_key_alias(key: str) -> str:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    aliases = {
        "serviceid": "service_id",
        "instanceid": "instance_id",
        "methodid": "method_id",
        "eventid": "event_id",
        "eventgroupid": "eventgroup_id",
        "requestid": "request_id",
        "sessionid": "session_id",
        "clientid": "client_id",
        "messageid": "message_id",
        "canid": "can_id",
        "timeout": "timeout",
        "ecuname": "ecu_name",
        "applicationname": "application_name",
    }
    for marker, alias in aliases.items():
        if marker in normalized:
            return alias
    return key[:MAX_TARGET_LENGTH]


def _add_target(targets: list[str], target: str) -> None:
    cleaned = target.strip()[:MAX_TARGET_LENGTH]
    if not cleaned:
        return
    if all(existing.casefold() != cleaned.casefold() for existing in targets):
        targets.append(cleaned)


def _report(callback: Optional[Callable[[str], None]], message: str) -> None:
    if callback:
        callback(message)
