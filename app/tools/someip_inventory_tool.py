"""Deterministic SOME/IP service inventory for configuration questions."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Optional

from app.orchestrator.evidence import Evidence
from app.tools.base import AnalysisTool
from app.tools.repository_inventory_tool import detect_question_intent
from input.models import AnalysisRequest


class SomeIpInventoryTool(AnalysisTool):
    """Count SOME/IP service interfaces, service IDs, and service instances from ARXML."""

    name = "SOME/IP Inventory"
    phase = 85

    def is_applicable(self, request: AnalysisRequest) -> bool:
        return (
            Path(request.repo_path).exists()
            and Path(request.repo_path).is_dir()
            and detect_question_intent(request.defect_description) == "someip_inventory"
        )

    def run(
        self,
        request: AnalysisRequest,
        on_progress: Optional[Callable[[str], None]] = None,
        prior_evidence: Optional[list[Evidence]] = None,
    ) -> Evidence:
        root = Path(request.repo_path).resolve(strict=True)
        if on_progress:
            on_progress("Scanning repository for SOME/IP service definitions and deployments...")

        files = sorted(_xml_files(root))
        interfaces: list[dict[str, Any]] = []
        instances: list[dict[str, Any]] = []
        malformed_files: list[str] = []

        for file_path in files:
            rel = file_path.relative_to(root).as_posix()
            try:
                tree = ET.parse(file_path)
            except (ET.ParseError, OSError, ValueError):
                malformed_files.append(rel)
                continue

            for element in tree.getroot().iter():
                tag = _local_name(element.tag)
                if tag.lower() in {"service-interface", "serviceinterface"}:
                    iface = _read_service_interface(element, rel)
                    if iface:
                        interfaces.append(iface)
                if tag.lower() in {"service-instance", "serviceinstance", "provided-service-instance", "required-service-instance"}:
                    instance = _read_service_instance(element, rel)
                    if instance:
                        instances.append(instance)

        unique_interfaces = _dedupe_by_name_and_id(interfaces)
        unique_ids = sorted({item["service_id"] for item in unique_interfaces if item["service_id"]})
        provided_instances = [
            item for item in instances if item.get("provided") is True
        ]
        required_instances = [
            item for item in instances if item.get("provided") is False
        ]

        details = {
            "query": request.defect_description,
            "intent": "someip_inventory",
            "files_inspected": len(files),
            "malformed_files": malformed_files,
            "unique_service_interfaces": len(unique_interfaces),
            "unique_service_ids": len(unique_ids),
            "provided_service_instances": len({(item.get("service_ref"), item.get("instance_id")) for item in provided_instances if item.get("service_ref") or item.get("instance_id")}),
            "required_service_instances": len({(item.get("service_ref"), item.get("instance_id")) for item in required_instances if item.get("service_ref") or item.get("instance_id")}),
            "service_interfaces": unique_interfaces,
            "service_instances": instances,
            "evidence_found": bool(unique_interfaces or instances),
        }

        summary = (
            f"SOME/IP inventory found {len(unique_interfaces)} unique service interfaces, "
            f"{len(unique_ids)} unique service IDs, {len({(item.get('service_ref'), item.get('instance_id')) for item in provided_instances if item.get('service_ref') or item.get('instance_id')})} provided instances, "
            f"and {len({(item.get('service_ref'), item.get('instance_id')) for item in required_instances if item.get('service_ref') or item.get('instance_id')})} required instances across {len(files)} XML files."
        )
        if not files:
            summary = "No XML/ARXML configuration files were available to enumerate SOME/IP services."
        if malformed_files:
            summary += " Malformed XML files were skipped."

        return Evidence(
            source="SOME/IP Inventory",
            summary=summary,
            details=details,
            severity="info",
        )


def _xml_files(root: Path) -> list[Path]:
    files: list[Path] = []
    if not root.exists():
        return files
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".arxml", ".xml"}:
            files.append(path)
    return files


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _first_text(element: Any, names: tuple[str, ...]) -> str:
    for child in element.iter():
        tag = _local_name(child.tag)
        if tag in names:
            text = (child.text or "").strip()
            if text:
                return text
    return ""


def _read_service_interface(element: ET.Element, source_file: str) -> dict[str, Any] | None:
    name = _first_text(element, ("SHORT-NAME", "SHORTNAME")) or element.attrib.get("SHORT-NAME") or element.attrib.get("name")
    service_id = _first_text(element, ("SERVICE-IDENTIFIER", "SERVICE-ID", "SERVICEID"))
    if not name:
        return None
    return {
        "name": name,
        "service_id": service_id,
        "source_file": source_file,
    }


def _read_service_instance(element: ET.Element, source_file: str) -> dict[str, Any] | None:
    name = _first_text(element, ("SHORT-NAME", "SHORTNAME")) or element.attrib.get("SHORT-NAME") or element.attrib.get("name")
    if not name:
        return None
    provided_text = _first_text(element, ("PROVIDED", "IS-PROVIDED", "PROVIDED-SERVICE"))
    service_ref = _first_text(element, ("SERVICE-REF", "SERVICE-REFERENCE"))
    instance_id = _first_text(element, ("SERVICE-INSTANCE-ID", "INSTANCE-ID", "INSTANCEID"))
    provided = None
    if provided_text:
        normalized = provided_text.strip().lower()
        provided = normalized in {"true", "1", "yes", "provided"}
    return {
        "name": name,
        "service_ref": service_ref,
        "instance_id": instance_id,
        "provided": provided,
        "source_file": source_file,
    }


def _dedupe_by_name_and_id(interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for item in interfaces:
        name = (item.get("name") or "").strip()
        service_id = (item.get("service_id") or "").strip()
        key = (name.lower(), service_id.lower())
        if key in unique:
            continue
        unique[key] = item
    return sorted(unique.values(), key=lambda entry: (entry.get("name", "").lower(), (entry.get("service_id") or "").lower()))
