"""Deterministic repository inventory and PDU counting for configuration questions."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Optional

from app.orchestrator.evidence import Evidence
from app.tools.base import AnalysisTool
from app.tools.repository_tool import discover_repository_files
from input.models import AnalysisRequest

PDU_TYPE_ALIASES = {
    "i-signal-i-pdu": "I-SIGNAL-I-PDU",
    "i-signal-group-i-pdu": "I-SIGNAL-GROUP-I-PDU",
    "n-pdu": "N-PDU",
    "dynamic-part-i-pdu": "DYNAMIC-PART-I-PDU",
    "multiplexed-i-pdu": "MULTIPLEXED-I-PDU",
    "general-purpose-i-pdu": "GENERAL-PURPOSE-I-PDU",
    "dcm-i-pdu": "DCM-I-PDU",
    "nm-pdu": "NM-PDU",
    "container-i-pdu": "CONTAINER-I-PDU",
    "can-pdu": "CAN-PDU",
    "ethernet-pdu": "ETHERNET-PDU",
    "i-pdu": "I-PDU",
    "pdu": "PDU",
}

INVENTORY_KEYWORDS = (
    "pdu",
    "pdus",
    "signal group",
    "signal groups",
    "dtc",
    "dtcs",
    "module",
    "modules",
    "arxml",
    "configuration",
    "configured",
    "present in the project",
    "how many",
    "count",
    "inventory",
    "list all",
)


def _is_repository_inventory_request(text: str) -> bool:
    inventory_indicators = (
        "how many",
        "count",
        "inventory",
        "present in the project",
        "list all",
        "which arxml",
        "which modules",
        "configured",
    )
    config_targets = (
        "pdu",
        "pdus",
        "signal group",
        "signal groups",
        "dtc",
        "dtcs",
        "module",
        "modules",
        "arxml",
        "configuration",
    )

    if any(token in text for token in inventory_indicators):
        if any(keyword in text for keyword in config_targets):
            return True

    if "configured" in text and any(keyword in text for keyword in config_targets):
        return True

    return False

QUESTION_INTENT_KEYS = {
    "repository_inventory": (
        "how many",
        "count",
        "inventory",
        "configured",
        "present in the project",
        "list all configured",
        "which arxml",
        "which modules",
    ),
    "repository_search": (
        "where is",
        "where are",
        "find",
        "locate",
        "configured",
    ),
    "defect_log_analysis": (
        "why",
        "fail",
        "failed",
        "failure",
        "fault",
        "timeout",
        "not working",
        "error",
    ),
    "autosar_requirement_lookup": (
        "requirement",
        "autosar requirement",
        "autosar",
    ),
}


def detect_question_intent(question: str) -> str:
    text = (question or "").strip().lower()
    if not text:
        return "repository_search"

    if "some/ip" in text or "someip" in text:
        if any(token in text for token in ("service", "services", "service id", "service ids", "service instance", "service instances", "subscription", "offer", "discovery")) and any(
            token in text for token in ("how many", "count", "inventory", "list all", "which service", "configured")
        ):
            return "someip_inventory"

    if any(token in text for token in QUESTION_INTENT_KEYS["autosar_requirement_lookup"]):
        if "requirement" in text or "autosar requirement" in text:
            return "autosar_requirement_lookup"

    if any(token in text for token in QUESTION_INTENT_KEYS["defect_log_analysis"]) and any(
        token in text for token in ("pdu", "transmission", "signal", "communication", "timeout", "subscription", "service")
    ):
        return "defect_log_analysis"

    if any(token in text for token in QUESTION_INTENT_KEYS["repository_search"]) and any(
        token in text for token in ("where", "find", "locate")
    ):
        return "repository_search"

    if (
        "what does this project do" in text
        or "explain the repository architecture" in text
        or "what is the purpose of the repositorytool" in text
        or "what is the purpose of this project" in text
        or "explain the project" in text
        or "repository architecture" in text
    ):
        return "project_explanation"

    if _is_repository_inventory_request(text):
        if any(token in text for token in ("pdu", "pdus", "signal group", "signal groups")):
            return "repository_inventory"
        if any(token in text for token in ("some/ip service", "someip service", "service instance", "service instances", "service id", "services")):
            return "someip_inventory"
        return "repository_inventory"

    if "requirement" in text or "autosar" in text:
        return "autosar_requirement_lookup"

    if any(token in text for token in ("why", "failure", "error", "fail", "timeout")):
        return "defect_log_analysis"

    return "mixed_investigation"


class RepositoryInventoryTool(AnalysisTool):
    """Inventory repository-backed configuration items such as PDUs and signal groups."""

    name = "Repository Inventory"
    phase = 90

    def is_applicable(self, request: AnalysisRequest) -> bool:
        path = Path(request.repo_path)
        return path.exists() and path.is_dir() and detect_question_intent(request.defect_description) == "repository_inventory"

    def run(
        self,
        request: AnalysisRequest,
        on_progress: Optional[Callable[[str], None]] = None,
        prior_evidence: Optional[list[Evidence]] = None,
    ) -> Evidence:
        root = Path(request.repo_path).resolve(strict=True)
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
        if on_progress:
            on_progress("Scanning repository configuration files for inventory details...")

        files = _discovery_files(root, excluded_paths)
        inventory = _inventory_from_repository(root, files)
        total = inventory["total_unique_pdu_definitions"]
        summary = (
            f"Repository inventory found {total} unique PDU definitions across "
            f"{inventory['files_inspected']} inspected configuration files."
        )
        if inventory["duplicate_definitions"]:
            summary += f" Duplicate definitions were identified in {len(inventory['duplicate_definitions'])} groups."
        details = {
            **inventory,
            "repository_name": root.name,
            "query": request.defect_description,
            "intent": detect_question_intent(request.defect_description),
            "evidence_found": total > 0,
        }
        return Evidence(
            source="Repository Inventory",
            summary=summary,
            details=details,
            severity="info",
        )


def _discovery_files(root: Path, excluded_paths: set[Path]) -> list[Path]:
    return [
        path
        for path in discover_repository_files(root, excluded_paths=excluded_paths)
        if _is_inventory_candidate(path)
    ]


def _is_inventory_candidate(path: Path) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in {".arxml", ".xml"}:
        return True
    if suffix in {".json", ".yaml", ".yml", ".cfg", ".conf", ".ini"}:
        return True
    return any(marker in name for marker in ("pdu", "signal", "dtc", "autosar", "ecu", "com", "can", "eth"))


def _inventory_from_repository(root: Path, files: list[Path]) -> dict[str, Any]:
    definitions: list[dict[str, Any]] = []
    seen_names: dict[str, dict[str, Any]] = {}
    duplicate_definitions: list[dict[str, Any]] = []
    type_breakdown: Counter[str] = Counter()
    technology_breakdown: Counter[str] = Counter()
    source_breakdown: Counter[str] = Counter()
    malformed_files: list[str] = []
    unsupported_files: list[str] = []
    references_skipped = 0
    files_inspected = 0

    for relative_path in sorted(files, key=lambda item: item.as_posix()):
        file_rel = relative_path.relative_to(root).as_posix()
        try:
            if relative_path.suffix.lower() in {".arxml", ".xml"}:
                tree = ET.parse(relative_path)
                files_inspected += 1
            elif relative_path.suffix.lower() in {".json"}:
                with relative_path.open("r", encoding="utf-8") as handle:
                    json.loads(handle.read())
                files_inspected += 1
            elif relative_path.suffix.lower() in {".yaml", ".yml", ".cfg", ".conf", ".ini"}:
                relative_path.read_text(encoding="utf-8")
                files_inspected += 1
            else:
                unsupported_files.append(file_rel)
                continue
        except ET.ParseError:
            malformed_files.append(file_rel)
            continue
        except (OSError, UnicodeDecodeError, ValueError):
            malformed_files.append(file_rel)
            continue

        if relative_path.suffix.lower() in {".arxml", ".xml"}:
            entries, refs = _extract_pdu_entries_from_xml(tree, file_rel)
            references_skipped += refs
            for entry in entries:
                normalized_name = _normalize_name(entry["name"])
                if not normalized_name:
                    continue
                if normalized_name in seen_names:
                    existing = seen_names[normalized_name]
                    duplicate = {
                        "name": existing["name"],
                        "type": existing["type"],
                        "files": sorted({existing["source_file"], file_rel}),
                        "occurrences": 2,
                    }
                    duplicate_definitions.append(duplicate)
                    continue
                seen_names[normalized_name] = entry
                definitions.append(entry)
                type_breakdown[entry["type"]] += 1
                source_breakdown[file_rel] += 1
                technology_breakdown.update(_technology_counts(entry))

    unique_definitions = sorted(
        definitions,
        key=lambda item: (item["name"].lower(), item["source_file"].lower()),
    )
    for item in unique_definitions:
        item["source_file"] = item["source_file"]
    for name, entry in seen_names.items():
        _ = name
    total = len(unique_definitions)

    return {
        "total_unique_pdu_definitions": total,
        "definitions": unique_definitions,
        "type_breakdown": dict(sorted(type_breakdown.items())),
        "communication_technology_breakdown": dict(sorted(technology_breakdown.items())),
        "source_file_breakdown": dict(sorted(source_breakdown.items())),
        "duplicate_definitions": duplicate_definitions,
        "references_skipped": references_skipped,
        "files_inspected": files_inspected,
        "malformed_files": malformed_files,
        "unsupported_formats": unsupported_files,
        "counting_methodology": (
            "Unique definitions were deduplicated by normalized PDU name; XML references "
            "such as PDU-REF elements were not counted as independent definitions."
        ),
        "limitations": [
            "Counts are based on configuration files that were discoverable and readable under repository safety rules.",
            "Files with unsupported or malformed XML were recorded, not silently treated as zero-PDU inputs.",
            "Technology counts are only reported when a CAN/Ethernet classification can be inferred from explicit names or file context.",
        ],
    }


def _extract_pdu_entries_from_xml(tree: ET.ElementTree, file_rel: str) -> tuple[list[dict[str, Any]], int]:
    entries: list[dict[str, Any]] = []
    references = 0
    root = tree.getroot()

    def walk(node: ET.Element, parent_name: str | None = None) -> None:
        nonlocal references
        tag_name = _local_name(node.tag)
        if tag_name and _is_pdu_definition_tag(tag_name):
            short_name = _extract_short_name(node)
            if short_name:
                entries.append(
                    {
                        "name": short_name,
                        "type": _canonicalize_pdu_type(tag_name),
                        "source_file": file_rel,
                        "definition_path": _element_path(node),
                    }
                )
        elif tag_name and "PDU" in tag_name.upper() and tag_name.upper().endswith("REF") and parent_name != "PDU-REF":
            references += 1

        for child in list(node):
            walk(child, tag_name)

    walk(root)
    return entries, references


def _is_pdu_definition_tag(tag_name: str) -> bool:
    key = _normalize_tag(tag_name)
    if key in PDU_TYPE_ALIASES:
        return True
    if key.endswith("pdu") and "ref" not in key and "-reference" not in key:
        return True
    return False


def _canonicalize_pdu_type(tag_name: str) -> str:
    key = _normalize_tag(tag_name)
    return PDU_TYPE_ALIASES.get(key, tag_name)


def _normalize_tag(tag_name: str) -> str:
    return tag_name.strip().lower().replace(" ", "-")


def _normalize_name(name: str) -> str:
    return re.sub(r"\s+", "", (name or "")).strip()


def _extract_short_name(element: ET.Element) -> str:
    for child in element.iter():
        if _local_name(child.tag) == "SHORT-NAME":
            text = (child.text or "").strip()
            if text:
                return text
    for attribute in ("name", "SHORT-NAME"):
        value = element.attrib.get(attribute)
        if value:
            return value.strip()
    return ""


def _element_path(element: ET.Element) -> str:
    parts: list[str] = []
    current = element
    while True:
        parent = getattr(current, "getparent", None)
        tag_name = _local_name(current.tag)
        if tag_name:
            parts.append(tag_name)
        if parent is None:
            break
        current = parent()
    return "/".join(reversed(parts))


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _technology_counts(entry: dict[str, Any]) -> list[str]:
    technology: list[str] = []
    haystack = " ".join(
        [
            entry.get("name", ""),
            entry.get("type", ""),
            entry.get("source_file", ""),
        ]
    ).lower()
    if "can" in haystack:
        technology.append("CAN")
    if "ethernet" in haystack:
        technology.append("Ethernet")
    if not technology:
        technology.append("Unclassified")
    return technology
