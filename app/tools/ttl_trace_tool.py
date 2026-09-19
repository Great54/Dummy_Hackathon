"""TTTech TTX Logger (TTL) analysis through an external TShark process."""

from __future__ import annotations

import csv
import logging
import os
import queue
import shutil
import struct
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Optional

from dotenv import load_dotenv

from app.orchestrator.cancellation import AnalysisCancelledError
from app.orchestrator.evidence import Evidence
from app.tools.base import AnalysisTool
from input.models import AnalysisRequest

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str], None]
DEFAULT_PACKET_LIMIT = 100_000
DEFAULT_TIMEOUT_SECONDS = 300
PROGRESS_INTERVAL = 10_000
MAX_EXAMPLES = 30
MAX_DISTINCT_VALUES = 2_048
MAX_STDERR_CHARACTERS = 8_192
MAX_XML_BYTES = 16 * 1024 * 1024

FIELD_NAMES = (
    "frame.number",
    "frame.time_epoch",
    "frame.interface_id",
    "frame.interface_name",
    "_ws.col.Protocol",
    "_ws.col.Info",
    "eth.src",
    "eth.dst",
    "eth.type",
    "vlan.id",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "tcp.srcport",
    "tcp.dstport",
    "can.id",
    "can.len",
    "canfd.flags.fdf",
    "canfd.flags.brs",
    "canfd.flags.esi",
    "can.flags.err",
    "someip.serviceid",
    "someip.methodid",
    "someip.messageid",
    "someip.clientid",
    "someip.sessionid",
    "someip.messagetype",
    "someip.returncode",
    "someipsd.entry.type",
    "someipsd.entry.serviceid",
    "someipsd.entry.instanceid",
    "someipsd.entry.ttl",
    "someipsd.entry.eventgroupid",
)
FIELD_INDEX = {name: index for index, name in enumerate(FIELD_NAMES)}


class TtlTraceAnalysisError(RuntimeError):
    """Controlled error raised when TShark cannot analyze a TTTech TTL trace."""


class TtlTraceTool(AnalysisTool):
    """Stream bounded TTTech TTL evidence from a separately installed TShark."""

    name = "TTTech TTL Analysis"

    def __init__(self, popen_factory: Any = subprocess.Popen) -> None:
        self._popen_factory = popen_factory
        self._cancel_event = threading.Event()
        self._process: Optional[subprocess.Popen[str]] = None
        self._process_lock = threading.Lock()

    def is_applicable(self, request: AnalysisRequest) -> bool:
        return bool(request.ttl_path and is_tttech_ttl(Path(request.ttl_path)))

    def cancel(self) -> None:
        self._cancel_event.set()
        with self._process_lock:
            process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    def run(
        self,
        request: AnalysisRequest,
        on_progress: Optional[ProgressCallback] = None,
        prior_evidence: Optional[list[Evidence]] = None,
    ) -> Evidence:
        path = _validate_ttl_path(request.ttl_path)
        if not is_tttech_ttl(path):
            raise TtlTraceAnalysisError(f"File is not a TTTech TTL trace: {path}")

        self._cancel_event.clear()
        tshark_path = find_tshark()
        if tshark_path is None:
            message = (
                "TTTech TTL analysis requires TShark. Please install Wireshark/TShark."
            )
            _report(on_progress, message)
            raise TtlTraceAnalysisError(message)

        packet_limit = _positive_int_env("TTL_TSHARK_PACKET_LIMIT", DEFAULT_PACKET_LIMIT)
        timeout_seconds = _positive_int_env(
            "TTL_TSHARK_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS
        )
        metadata = read_tttech_metadata(path)
        version = _tshark_version(tshark_path)
        command = _build_command(tshark_path, path, packet_limit)

        _report(
            on_progress,
            f"TShark {version} detected. Analyzing up to {packet_limit:,} TTL records...",
        )
        logger.info(
            "Starting TShark TTL analysis path=%s size_bytes=%d packet_limit=%d timeout=%d",
            path,
            path.stat().st_size,
            packet_limit,
            timeout_seconds,
        )

        started = time.monotonic()
        stats = _new_stats()
        process = self._start_process(command)
        try:
            stderr_text = self._consume_process(
                process,
                stats,
                started,
                timeout_seconds,
                on_progress,
            )
        finally:
            _terminate_process(process)
            with self._process_lock:
                self._process = None

        elapsed = time.monotonic() - started
        details = _finalize_stats(
            path,
            metadata,
            stats,
            version,
            packet_limit,
            elapsed,
            stderr_text,
        )
        _report(
            on_progress,
            f"TTTech TTL extraction complete: {stats['records_processed']:,} records analyzed.",
        )
        return Evidence(
            source="TTTech TTL / TShark Analysis",
            summary=_summary(details),
            details=details,
            severity="warning" if details["error_record_count"] else "info",
        )

    def _start_process(self, command: list[str]) -> subprocess.Popen[str]:
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            process = self._popen_factory(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creation_flags,
            )
        except OSError as error:
            raise TtlTraceAnalysisError(f"Unable to start TShark: {error}") from error
        with self._process_lock:
            self._process = process
        return process

    def _consume_process(
        self,
        process: subprocess.Popen[str],
        stats: dict[str, Any],
        started: float,
        timeout_seconds: int,
        on_progress: Optional[ProgressCallback],
    ) -> str:
        output_queue: queue.Queue[tuple[str, Optional[str]]] = queue.Queue(maxsize=1024)
        stderr_parts: list[str] = []

        def read_stream(label: str, stream: Any) -> None:
            try:
                for line in stream:
                    output_queue.put((label, line))
            finally:
                output_queue.put((label, None))

        stdout_thread = threading.Thread(
            target=read_stream, args=("stdout", process.stdout), daemon=True
        )
        stderr_thread = threading.Thread(
            target=read_stream, args=("stderr", process.stderr), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()

        completed_streams: set[str] = set()
        while len(completed_streams) < 2:
            if self._cancel_event.is_set():
                _terminate_process(process)
                raise AnalysisCancelledError("Analysis cancelled by the user.")
            if time.monotonic() - started > timeout_seconds:
                _terminate_process(process)
                raise TtlTraceAnalysisError(
                    f"TShark analysis exceeded the {timeout_seconds}-second timeout. "
                    "Increase TTL_TSHARK_TIMEOUT_SECONDS to allow a longer scan."
                )

            try:
                label, line = output_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if line is None:
                completed_streams.add(label)
                continue
            if label == "stderr":
                _append_bounded(stderr_parts, line)
                continue

            row = next(csv.reader([line], delimiter="\t", quotechar='"'))
            _consume_row(row, stats)
            processed = stats["records_processed"]
            if processed and processed % PROGRESS_INTERVAL == 0:
                elapsed = max(time.monotonic() - started, 0.001)
                _report(
                    on_progress,
                    f"TShark analyzed {processed:,} TTL records "
                    f"({processed / elapsed:,.0f} records/second)...",
                )

        return_code = process.wait(timeout=5)
        stderr_text = "".join(stderr_parts).strip()
        if return_code != 0:
            message = _last_stderr_line(stderr_text) or "Unknown TShark error."
            raise TtlTraceAnalysisError(f"TShark failed: {message}")
        return stderr_text


def is_tttech_ttl(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4) == b"TTL "
    except OSError:
        return False


def find_tshark() -> Optional[str]:
    load_dotenv()
    configured = os.getenv("TSHARK_PATH", "").strip()
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return str(path)
        return None

    discovered = shutil.which("tshark")
    if discovered:
        return discovered

    if os.name == "nt":
        try:
            import winreg

            for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe",
                        0,
                        winreg.KEY_READ | view,
                    ) as key:
                        directory, _ = winreg.QueryValueEx(key, "Path")
                        candidate = Path(directory) / "tshark.exe"
                        if candidate.is_file():
                            return str(candidate)
                except OSError:
                    continue
        except ImportError:
            pass
    return None


def read_tttech_metadata(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        fixed_header = stream.read(16)
        if len(fixed_header) != 16:
            raise TtlTraceAnalysisError("TTTech TTL header is incomplete.")
        magic, version, block_size, header_size = struct.unpack("<4sIII", fixed_header)
        if magic != b"TTL " or header_size < 16 or header_size > MAX_XML_BYTES:
            raise TtlTraceAnalysisError("TTTech TTL header contains invalid sizes.")

        metadata: dict[str, Any] = {
            "format": "TTTech TTX Logger TTL",
            "format_version": version,
            "block_size_bytes": block_size,
            "header_size_bytes": header_size,
            "logger_type": None,
            "configuration_format_version": None,
            "creation_date": None,
            "configured_interfaces": [],
        }
        if header_size <= 4096:
            return metadata

        stream.seek(4096)
        xml_bytes = stream.read(header_size - 4096).rstrip(b" \t\r\n\x00")

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        logger.warning("TShark TTL header XML could not be parsed")
        return metadata

    metadata["logger_type"] = root.findtext("LoggerType")
    metadata["configuration_format_version"] = root.findtext("ConfigFormatVersion")
    metadata["creation_date"] = root.findtext("CreationDate")
    interfaces: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for function in root.findall(".//Function"):
        label = (function.findtext("InterfaceLabel") or "").strip()
        user_name = (function.findtext("UserDefinedName") or "").strip()
        key = (label, user_name)
        if label and key not in seen and len(interfaces) < 100:
            interfaces.append({"label": label, "user_name": user_name or None})
            seen.add(key)
    metadata["configured_interfaces"] = interfaces
    return metadata


def _build_command(tshark_path: str, path: Path, packet_limit: int) -> list[str]:
    command = [
        tshark_path,
        "-n",
        "-l",
        "-r",
        str(path),
        "-c",
        str(packet_limit),
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in FIELD_NAMES:
        command.extend(("-e", field))
    return command


def _new_stats() -> dict[str, Any]:
    return {
        "records_processed": 0,
        "first_timestamp": None,
        "last_timestamp": None,
        "protocol_counts": Counter(),
        "interface_counts": Counter(),
        "ethernet_frame_count": 0,
        "ipv4_frame_count": 0,
        "ipv6_frame_count": 0,
        "udp_frame_count": 0,
        "tcp_frame_count": 0,
        "can_frame_count": 0,
        "can_fd_frame_count": 0,
        "error_record_count": 0,
        "someip_message_count": 0,
        "someip_sd_entry_count": 0,
        "ip_endpoints": Counter(),
        "transport_endpoints": Counter(),
        "can_ids": Counter(),
        "someip_services": Counter(),
        "examples": [],
        "someip_examples": [],
        "someip_sd_examples": [],
        "values_not_tracked_after_capacity": 0,
    }


def _consume_row(row: list[str], stats: dict[str, Any]) -> None:
    if len(row) < len(FIELD_NAMES):
        row.extend([""] * (len(FIELD_NAMES) - len(row)))
    values = {field: row[index].strip() for field, index in FIELD_INDEX.items()}
    if not values["frame.number"]:
        return

    stats["records_processed"] += 1
    timestamp = _float_or_none(values["frame.time_epoch"])
    if timestamp is not None:
        if stats["first_timestamp"] is None:
            stats["first_timestamp"] = timestamp
        stats["last_timestamp"] = timestamp

    protocol = values["_ws.col.Protocol"] or "Unknown"
    _bounded_increment(stats["protocol_counts"], protocol, stats)
    interface = values["frame.interface_name"] or values["frame.interface_id"] or "Unknown"
    _bounded_increment(stats["interface_counts"], interface, stats)

    if values["eth.src"] or values["eth.dst"]:
        stats["ethernet_frame_count"] += 1
    if values["ip.src"] or values["ip.dst"]:
        stats["ipv4_frame_count"] += 1
    if values["ipv6.src"] or values["ipv6.dst"]:
        stats["ipv6_frame_count"] += 1
    if values["udp.srcport"] or values["udp.dstport"]:
        stats["udp_frame_count"] += 1
    if values["tcp.srcport"] or values["tcp.dstport"]:
        stats["tcp_frame_count"] += 1
    if values["can.id"]:
        stats["can_frame_count"] += 1
        _bounded_increment(stats["can_ids"], values["can.id"], stats)
    if values["canfd.flags.fdf"] or protocol.upper() == "CANFD":
        stats["can_fd_frame_count"] += 1
    if values["can.flags.err"] or "error" in values["_ws.col.Info"].lower():
        stats["error_record_count"] += 1

    source_ip = values["ip.src"] or values["ipv6.src"]
    destination_ip = values["ip.dst"] or values["ipv6.dst"]
    if source_ip or destination_ip:
        _bounded_increment(
            stats["ip_endpoints"], f"{source_ip or '?'} -> {destination_ip or '?'}", stats
        )
    source_port = values["udp.srcport"] or values["tcp.srcport"]
    destination_port = values["udp.dstport"] or values["tcp.dstport"]
    if source_port or destination_port:
        transport = "UDP" if values["udp.srcport"] else "TCP"
        _bounded_increment(
            stats["transport_endpoints"],
            f"{transport} {source_ip or '?'}:{source_port or '?'} -> "
            f"{destination_ip or '?'}:{destination_port or '?'}",
            stats,
        )

    if values["someip.serviceid"]:
        stats["someip_message_count"] += 1
        service_key = (
            f"{values['someip.serviceid']} / {values['someip.methodid'] or '?'}"
        )
        _bounded_increment(stats["someip_services"], service_key, stats)
        if len(stats["someip_examples"]) < MAX_EXAMPLES:
            stats["someip_examples"].append(
                _selected(values, (
                    "frame.number", "frame.time_epoch", "frame.interface_name",
                    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                    "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport",
                    "someip.serviceid", "someip.methodid", "someip.messageid",
                    "someip.clientid", "someip.sessionid",
                    "someip.messagetype", "someip.returncode",
                ))
            )

    if values["someipsd.entry.type"]:
        stats["someip_sd_entry_count"] += 1
        if len(stats["someip_sd_examples"]) < MAX_EXAMPLES:
            stats["someip_sd_examples"].append(
                _selected(values, (
                    "frame.number", "frame.time_epoch", "frame.interface_name",
                    "ip.src", "ip.dst", "someipsd.entry.type",
                    "someipsd.entry.serviceid", "someipsd.entry.instanceid",
                    "someipsd.entry.ttl", "someipsd.entry.eventgroupid",
                ))
            )

    if len(stats["examples"]) < MAX_EXAMPLES:
        stats["examples"].append(
            _selected(values, (
                "frame.number", "frame.time_epoch", "frame.interface_name",
                "_ws.col.Protocol", "_ws.col.Info", "eth.src", "eth.dst",
                "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport",
                "can.id", "can.len",
            ))
        )


def _finalize_stats(
    path: Path,
    metadata: dict[str, Any],
    stats: dict[str, Any],
    tshark_version: str,
    packet_limit: int,
    elapsed: float,
    stderr_text: str,
) -> dict[str, Any]:
    first = stats["first_timestamp"]
    last = stats["last_timestamp"]
    return {
        "source_file": path.name,
        "file_path": str(path.resolve()),
        "file_size_bytes": path.stat().st_size,
        "logger_metadata": metadata,
        "tshark_version": tshark_version,
        "records_processed": stats["records_processed"],
        "packet_limit": packet_limit,
        "analysis_scope": (
            f"First {packet_limit:,} decoded records; this is not a full-file conclusion."
        ),
        "elapsed_seconds": round(elapsed, 3),
        "first_timestamp_epoch": first,
        "last_timestamp_epoch": last,
        "capture_duration_seconds": (
            round(last - first, 6) if first is not None and last is not None else None
        ),
        "protocol_counts": dict(stats["protocol_counts"].most_common(30)),
        "interface_counts": dict(stats["interface_counts"].most_common(50)),
        "ethernet_frame_count": stats["ethernet_frame_count"],
        "ipv4_frame_count": stats["ipv4_frame_count"],
        "ipv6_frame_count": stats["ipv6_frame_count"],
        "udp_frame_count": stats["udp_frame_count"],
        "tcp_frame_count": stats["tcp_frame_count"],
        "can_frame_count": stats["can_frame_count"],
        "can_fd_frame_count": stats["can_fd_frame_count"],
        "error_record_count": stats["error_record_count"],
        "someip_message_count": stats["someip_message_count"],
        "someip_sd_entry_count": stats["someip_sd_entry_count"],
        "top_ip_endpoints": dict(stats["ip_endpoints"].most_common(30)),
        "top_transport_endpoints": dict(stats["transport_endpoints"].most_common(30)),
        "top_can_ids": dict(stats["can_ids"].most_common(30)),
        "top_someip_service_methods": dict(
            stats["someip_services"].most_common(30)
        ),
        "record_examples": stats["examples"],
        "someip_examples": stats["someip_examples"],
        "someip_sd_examples": stats["someip_sd_examples"],
        "values_not_tracked_after_capacity": stats[
            "values_not_tracked_after_capacity"
        ],
        "tshark_warnings": stderr_text[-MAX_STDERR_CHARACTERS:] if stderr_text else "",
        "raw_ttl_content_returned": False,
        "converted_capture_created": False,
    }


def _summary(details: dict[str, Any]) -> str:
    return (
        f"TShark analyzed {details['records_processed']:,} TTTech TTL records "
        f"(limit {details['packet_limit']:,}): "
        f"{details['ethernet_frame_count']:,} Ethernet, "
        f"{details['can_frame_count']:,} CAN/CAN-FD, "
        f"{details['someip_message_count']:,} SOME/IP, and "
        f"{details['someip_sd_entry_count']:,} SOME/IP-SD entries. "
        "Counts apply only to the analyzed record window."
    )


def _tshark_version(tshark_path: str) -> str:
    try:
        result = subprocess.run(
            [tshark_path, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TtlTraceAnalysisError(f"Unable to query TShark version: {error}") from error
    if result.returncode != 0:
        raise TtlTraceAnalysisError("TShark was found but did not start successfully.")
    first_line = result.stdout.splitlines()[0] if result.stdout else "TShark"
    return first_line.replace("TShark (Wireshark) ", "").rstrip(".")


def _validate_ttl_path(path_text: str | None) -> Path:
    if not path_text:
        raise TtlTraceAnalysisError("No TTL path was supplied.")
    path = Path(path_text)
    if not path.exists() or not path.is_file():
        raise TtlTraceAnalysisError(f"TTTech TTL file does not exist: {path}")
    return path


def _positive_int_env(name: str, default: int) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError as error:
        raise TtlTraceAnalysisError(f"{name} must be a positive integer.") from error
    if parsed <= 0:
        raise TtlTraceAnalysisError(f"{name} must be a positive integer.")
    return parsed


def _bounded_increment(counter: Counter[str], key: str, stats: dict[str, Any]) -> None:
    if key in counter or len(counter) < MAX_DISTINCT_VALUES:
        counter[key] += 1
    else:
        stats["values_not_tracked_after_capacity"] += 1


def _selected(values: dict[str, str], fields: tuple[str, ...]) -> dict[str, str]:
    return {field: values[field] for field in fields if values.get(field)}


def _float_or_none(value: str) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _append_bounded(parts: list[str], value: str) -> None:
    current_size = sum(len(part) for part in parts)
    remaining = MAX_STDERR_CHARACTERS - current_size
    if remaining > 0:
        parts.append(value[:remaining])


def _last_stderr_line(stderr_text: str) -> str:
    lines = [line.strip() for line in stderr_text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _report(callback: Optional[ProgressCallback], message: str) -> None:
    logger.info(message)
    if callback:
        callback(message)
