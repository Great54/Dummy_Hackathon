"""Streaming Vector BLF analysis for CAN/CAN-FD and supported Ethernet objects."""

from __future__ import annotations

import logging
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Optional

from vblf.can import (
    CanErrorFrame,
    CanErrorFrameExt,
    CanFdErrorFrame64,
    CanFdMessage,
    CanFdMessage64,
    CanMessage,
    CanMessage2,
)
from vblf.constants import ObjFlags, ObjType
from vblf.ethernet import EthernetFrameEx, EthernetStatistic
from vblf.general import NotImplementedObject
from vblf.reader import BlfReader

from app.orchestrator.evidence import Evidence
from app.tools.base import AnalysisTool
from app.tools.protocols.ethernet_parser import (
    classify_ether_type,
    parse_ethernet_frame,
)
from app.tools.protocols.someip_parser import (
    SD_MESSAGE_ID,
    SomeIpStats,
    parse_someip,
)
from app.tools.protocols.someip_sd_parser import parse_someip_sd
from input.models import AnalysisRequest

logger = logging.getLogger(__name__)

MAX_CAN_IDS = 4096
MAX_CAN_EXAMPLES = 20
MAX_ETHERNET_EXAMPLES = 20
MAX_TOP_ITEMS = 20
MAX_SD_EXAMPLES = 20
CAN_EXTENDED_FLAG = 0x80000000

CAN_TYPES = (CanMessage, CanMessage2)
CAN_FD_TYPES = (CanFdMessage, CanFdMessage64)
CAN_ERROR_TYPES = (CanErrorFrame, CanErrorFrameExt, CanFdErrorFrame64)
ETHERNET_ERROR_TYPES = {
    ObjType.ETHERNET_RX_ERROR,
    ObjType.ETHERNET_ERROR_EX,
    ObjType.ETHERNET_ERROR_FORWARDED,
}
ETHERNET_STATUS_TYPES = {
    ObjType.ETHERNET_STATUS,
    ObjType.ETHERNET_STATISTIC,
}


class BlfAnalysisError(RuntimeError):
    """Controlled error raised when a BLF cannot be analyzed."""


class BlfTool(AnalysisTool):
    """Iteratively extract bounded CAN, Ethernet and SOME/IP evidence from BLF."""

    name = "BLF Analysis"

    def is_applicable(self, request: AnalysisRequest) -> bool:
        return bool(request.blf_path)

    def run(
        self,
        request: AnalysisRequest,
        on_progress: Optional[Callable[[str], None]] = None,
        prior_evidence: Optional[list[Evidence]] = None,
    ) -> Evidence:
        path = self._validate_path(request.blf_path)
        try:
            return self._analyze(path, request.defect_description)
        except (OSError, ValueError, EOFError) as error:
            logger.exception("Unable to parse BLF file %s", path)
            raise BlfAnalysisError(f"Unable to parse BLF file: {error}") from error

    @staticmethod
    def _validate_path(path_text: str | None) -> Path:
        if not path_text:
            raise BlfAnalysisError("No BLF path was supplied.")
        path = Path(path_text)
        if path.suffix.lower() != ".blf":
            raise BlfAnalysisError(f"Selected file is not a .blf file: {path}")
        if not path.exists():
            raise BlfAnalysisError(f"BLF file does not exist: {path}")
        if not path.is_file():
            raise BlfAnalysisError(f"BLF path is not a file: {path}")
        return path

    def _analyze(self, path: Path, defect_description: str) -> Evidence:
        stats: dict[str, Any] = {
            "total_objects_processed": 0,
            "detected_object_types": Counter(),
            "first_timestamp_seconds": None,
            "last_timestamp_seconds": None,
            "channels": set(),
            "can_message_count": 0,
            "can_fd_message_count": 0,
            "ethernet_frame_count": 0,
            "error_frame_count": 0,
            "ethernet_error_count": 0,
            "ethernet_status_count": 0,
            "unsupported_object_count": 0,
            "can_ids": {},
            "can_ids_not_tracked": 0,
            "can_examples": [],
            "ethernet_protocols": Counter(),
            "ethernet_examples": [],
            "someip": SomeIpStats(),
            "someip_sd": [],
        }

        try:
            with BlfReader(path) as reader:
                file_statistics = reader.file_statistics
                for obj in reader:
                    self._process_object(obj, stats)
        except PermissionError as error:
            logger.exception("Permission denied reading BLF file %s", path)
            raise BlfAnalysisError(f"Permission denied reading BLF file: {path}") from error
        except BlfAnalysisError:
            raise
        except Exception as error:  # vblf can raise struct/zlib errors for corruption
            logger.exception("BLF parser failed for %s", path)
            raise BlfAnalysisError(
                f"BLF is invalid, corrupted, or uses an unsupported object encoding: {error}"
            ) from error

        details = self._finalize(path, defect_description, file_statistics, stats)
        summary = self._summary(details)
        severity = "warning" if details["error_frame_count"] else "info"
        return Evidence(
            source="BLF / CAN and Ethernet Analysis",
            summary=summary,
            details=details,
            severity=severity,
        )

    def _process_object(self, obj: Any, stats: dict[str, Any]) -> None:
        object_type = obj.header.base.object_type
        timestamp = _timestamp_seconds(obj)
        stats["total_objects_processed"] += 1
        stats["detected_object_types"][object_type.name] += 1
        _update_timestamp_range(stats, timestamp)

        channel = getattr(obj, "channel", None)
        if channel is not None:
            stats["channels"].add(channel)

        if isinstance(obj, CAN_TYPES):
            stats["can_message_count"] += 1
            self._process_can(obj, timestamp, stats, is_fd=False)
        elif isinstance(obj, CAN_FD_TYPES):
            stats["can_fd_message_count"] += 1
            self._process_can(obj, timestamp, stats, is_fd=True)
        elif isinstance(obj, CAN_ERROR_TYPES):
            stats["error_frame_count"] += 1
        elif isinstance(obj, EthernetFrameEx):
            stats["ethernet_frame_count"] += 1
            self._process_ethernet(obj, timestamp, stats)
        elif isinstance(obj, EthernetStatistic):
            stats["ethernet_status_count"] += 1
        elif object_type in ETHERNET_ERROR_TYPES:
            stats["ethernet_error_count"] += 1
        elif object_type in ETHERNET_STATUS_TYPES:
            stats["ethernet_status_count"] += 1

        if isinstance(obj, NotImplementedObject):
            stats["unsupported_object_count"] += 1

    def _process_can(
        self, obj: Any, timestamp: float, stats: dict[str, Any], *, is_fd: bool
    ) -> None:
        raw_id = obj.frame_id
        can_id = raw_id & ~CAN_EXTENDED_FLAG
        key = (can_id, bool(raw_id & CAN_EXTENDED_FLAG), obj.channel)
        tracked = stats["can_ids"]
        item = tracked.get(key)
        if item is None:
            if len(tracked) >= MAX_CAN_IDS:
                stats["can_ids_not_tracked"] += 1
                return
            item = {
                "can_id": f"0x{can_id:X}",
                "extended": key[1],
                "channel": obj.channel,
                "count": 0,
                "first_timestamp_seconds": timestamp,
                "last_timestamp_seconds": timestamp,
                "dlc": obj.dlc,
                "payload_length": _can_payload_length(obj, is_fd),
                "can_fd": is_fd,
            }
            tracked[key] = item
        item["count"] += 1
        item["last_timestamp_seconds"] = timestamp

        examples = stats["can_examples"]
        if len(examples) < MAX_CAN_EXAMPLES:
            examples.append(dict(item))

    def _process_ethernet(
        self, obj: EthernetFrameEx, timestamp: float, stats: dict[str, Any]
    ) -> None:
        frame = obj.frame_data[: obj.frame_length]
        protocol_name, ether_type, vlan_ids = classify_ether_type(frame)
        stats["ethernet_protocols"][protocol_name] += 1

        transport = parse_ethernet_frame(frame)
        example: dict[str, Any] = {
            "channel": obj.channel,
            "hardware_channel": obj.hardware_channel,
            "timestamp_seconds": timestamp,
            "direction": _direction_name(obj.dir),
            "frame_length": obj.frame_length,
            "protocol": protocol_name,
            "ether_type": f"0x{ether_type:04X}" if ether_type is not None else None,
            "vlan_ids": list(vlan_ids),
        }
        if transport:
            example.update(
                {
                    "source_mac": transport.source_mac,
                    "destination_mac": transport.destination_mac,
                    "source_ip": transport.source_ip,
                    "destination_ip": transport.destination_ip,
                    "transport": transport.transport,
                    "source_port": transport.source_port,
                    "destination_port": transport.destination_port,
                }
            )
            someip = parse_someip(transport.payload)
            if someip:
                context = {
                    "timestamp": timestamp,
                    "source_ip": transport.source_ip,
                    "destination_ip": transport.destination_ip,
                    "source_port": transport.source_port,
                    "destination_port": transport.destination_port,
                    "transport": transport.transport,
                }
                stats["someip"].add(someip, context)
                if someip.message_id == SD_MESSAGE_ID:
                    sd = parse_someip_sd(someip)
                    if sd["valid"] and len(stats["someip_sd"]) < MAX_SD_EXAMPLES:
                        stats["someip_sd"].append(sd)

        if len(stats["ethernet_examples"]) < MAX_ETHERNET_EXAMPLES:
            stats["ethernet_examples"].append(example)

    def _finalize(
        self,
        path: Path,
        defect_description: str,
        file_statistics: Any,
        stats: dict[str, Any],
    ) -> dict[str, Any]:
        first = stats["first_timestamp_seconds"]
        last = stats["last_timestamp_seconds"]
        top_can_ids = sorted(
            stats["can_ids"].values(), key=lambda item: item["count"], reverse=True
        )[:MAX_TOP_ITEMS]
        someip = stats["someip"].to_dict()

        return {
            "file_path": str(path.resolve()),
            "file_size_bytes": path.stat().st_size,
            "header_object_count": file_statistics.object_count,
            "total_objects_processed": stats["total_objects_processed"],
            "detected_object_types": dict(stats["detected_object_types"]),
            "first_timestamp_seconds": first,
            "last_timestamp_seconds": last,
            "duration_seconds": last - first if first is not None and last is not None else None,
            "measurement_start_time": _safe_datetime(file_statistics.measurement_start_time),
            "measurement_end_time": _safe_datetime(file_statistics.last_object_time),
            "channels": sorted(stats["channels"]),
            "can_message_count": stats["can_message_count"],
            "can_fd_message_count": stats["can_fd_message_count"],
            "ethernet_frame_count": stats["ethernet_frame_count"],
            "error_frame_count": stats["error_frame_count"],
            "ethernet_error_count": stats["ethernet_error_count"],
            "ethernet_status_count": stats["ethernet_status_count"],
            "unsupported_object_count": stats["unsupported_object_count"],
            "top_can_ids": top_can_ids,
            "can_ids_not_tracked_after_capacity": stats["can_ids_not_tracked"],
            "can_examples": stats["can_examples"],
            "ethernet_protocol_counts": dict(stats["ethernet_protocols"]),
            "ethernet_examples": stats["ethernet_examples"],
            "someip": someip,
            "someip_sd": stats["someip_sd"],
            "defect_context": defect_description,
            "possible_relevance": _possible_relevance(defect_description, someip),
            "analysis_limits": {
                "can_id_capacity": MAX_CAN_IDS,
                "top_can_ids_returned": MAX_TOP_ITEMS,
                "can_examples_returned": MAX_CAN_EXAMPLES,
                "ethernet_examples_returned": MAX_ETHERNET_EXAMPLES,
                "someip_examples_returned": 20,
                "service_payload_decoding": "not attempted without service definitions",
                "ethernet_support": (
                    "EthernetFrameEx payloads parsed; other Ethernet object variants "
                    "are counted but may be unsupported by the selected BLF library"
                ),
            },
        }

    @staticmethod
    def _summary(details: dict[str, Any]) -> str:
        parts = [
            f"Processed {details['total_objects_processed']} BLF objects",
            f"{details['can_message_count']} CAN messages",
            f"{details['can_fd_message_count']} CAN-FD messages",
            f"{details['ethernet_frame_count']} extractable Ethernet frames",
        ]
        someip_count = details["someip"]["message_count"]
        if someip_count:
            parts.append(f"{someip_count} conservatively validated SOME/IP messages")
        if details["unsupported_object_count"]:
            parts.append(
                f"{details['unsupported_object_count']} unsupported objects counted"
            )
        return "; ".join(parts) + "."


def _timestamp_seconds(obj: Any) -> float:
    header = obj.header
    raw = getattr(header, "object_time_stamp", 0)
    flags = getattr(header, "object_flags", ObjFlags.TIME_ONE_NANS)
    return raw * (1e-5 if flags & ObjFlags.TIME_TEN_MICS else 1e-9)


def _update_timestamp_range(stats: dict[str, Any], timestamp: float) -> None:
    if stats["first_timestamp_seconds"] is None:
        stats["first_timestamp_seconds"] = timestamp
    stats["last_timestamp_seconds"] = timestamp


def _can_payload_length(obj: Any, is_fd: bool) -> int:
    if is_fd:
        return int(getattr(obj, "valid_data_bytes", len(obj.data)))
    return min(int(obj.dlc), len(obj.data))


def _direction_name(direction: int) -> str:
    return {0: "received", 1: "transmitted"}.get(direction, f"unknown_{direction}")


def _safe_datetime(system_time: Any) -> str | None:
    try:
        return system_time.to_datetime().isoformat()
    except (ValueError, OverflowError):
        return None


def _possible_relevance(defect: str, someip: dict[str, Any]) -> str:
    normalized = defect.lower()
    mentions_someip = "some/ip" in normalized or "someip" in normalized
    if mentions_someip and someip["message_count"]:
        return (
            "The defect mentions SOME/IP and validated SOME/IP headers were observed. "
            "Request/response statistics are included; unmatched counts only describe "
            "the analyzed capture interval and do not prove network loss."
        )
    if mentions_someip:
        return (
            "The defect mentions SOME/IP, but no conservatively validated SOME/IP "
            "messages were found in extractable EthernetFrameEx objects. This does "
            "not prove SOME/IP was absent if the BLF used unsupported object variants."
        )
    return (
        "No protocol-specific relevance was inferred from the defect text; the "
        "statistics are confirmed capture facts for later correlation."
    )
