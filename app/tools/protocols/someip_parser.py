"""Bounded SOME/IP header parsing and request/response correlation."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Optional

SOMEIP_HEADER = struct.Struct("!IIII")
VALID_MESSAGE_TYPES = {
    0x00: "request",
    0x01: "request_no_return",
    0x02: "notification",
    0x20: "tp_request",
    0x21: "tp_request_no_return",
    0x22: "tp_notification",
    0x80: "response",
    0x81: "error",
    0xA0: "tp_response",
    0xA1: "tp_error",
}
SD_MESSAGE_ID = 0xFFFF8100
MAX_EXAMPLES = 20
MAX_PENDING_REQUESTS = 4096


@dataclass(frozen=True)
class SomeIpMessage:
    message_id: int
    service_id: int
    method_id: int
    length: int
    request_id: int
    client_id: int
    session_id: int
    protocol_version: int
    interface_version: int
    message_type: int
    message_type_name: str
    return_code: int
    payload: bytes


def parse_someip(payload: bytes) -> Optional[SomeIpMessage]:
    """Parse one complete SOME/IP message after conservative validation."""

    if len(payload) < 16:
        return None
    message_id, length, request_id, trailer = SOMEIP_HEADER.unpack_from(payload)
    protocol_version = trailer >> 24
    interface_version = (trailer >> 16) & 0xFF
    message_type = (trailer >> 8) & 0xFF
    return_code = trailer & 0xFF
    total_length = 8 + length

    if (
        protocol_version != 1
        or length < 8
        or total_length > len(payload)
        or message_type not in VALID_MESSAGE_TYPES
    ):
        return None

    return SomeIpMessage(
        message_id=message_id,
        service_id=message_id >> 16,
        method_id=message_id & 0xFFFF,
        length=length,
        request_id=request_id,
        client_id=request_id >> 16,
        session_id=request_id & 0xFFFF,
        protocol_version=protocol_version,
        interface_version=interface_version,
        message_type=message_type,
        message_type_name=VALID_MESSAGE_TYPES[message_type],
        return_code=return_code,
        payload=payload[16:total_length],
    )


def message_to_dict(
    message: SomeIpMessage,
    *,
    timestamp: float,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    transport: str,
) -> dict[str, Any]:
    """Return bounded JSON-safe header evidence; application payload stays local."""

    return {
        "message_id": f"0x{message.message_id:08X}",
        "service_id": f"0x{message.service_id:04X}",
        "method_id": f"0x{message.method_id:04X}",
        "length": message.length,
        "request_id": f"0x{message.request_id:08X}",
        "client_id": f"0x{message.client_id:04X}",
        "session_id": f"0x{message.session_id:04X}",
        "protocol_version": message.protocol_version,
        "interface_version": message.interface_version,
        "message_type": message.message_type_name,
        "return_code": message.return_code,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "timestamp_seconds": timestamp,
        "transport": transport,
        "payload_length": len(message.payload),
        "payload_sample_hex": message.payload[:16].hex(),
    }


class SomeIpStats:
    """Bounded SOME/IP statistics and request/response correlation state."""

    def __init__(self) -> None:
        self.message_count = 0
        self.request_count = 0
        self.response_count = 0
        self.notification_count = 0
        self.unmatched_responses = 0
        self.examples: list[dict[str, Any]] = []
        self._pending: dict[tuple[int, int, int], float] = {}
        self._latencies: list[float] = []
        self.pending_overflow = 0

    def add(self, message: SomeIpMessage, context: dict[str, Any]) -> None:
        self.message_count += 1
        if len(self.examples) < MAX_EXAMPLES:
            self.examples.append(message_to_dict(message, **context))

        key = (message.message_id, message.client_id, message.session_id)
        if message.message_type_name in {"request", "tp_request"}:
            self.request_count += 1
            if len(self._pending) < MAX_PENDING_REQUESTS:
                self._pending[key] = context["timestamp"]
            else:
                self.pending_overflow += 1
        elif message.message_type_name in {"response", "error", "tp_response", "tp_error"}:
            self.response_count += 1
            request_timestamp = self._pending.pop(key, None)
            if request_timestamp is None:
                self.unmatched_responses += 1
            else:
                self._latencies.append(context["timestamp"] - request_timestamp)
        elif "notification" in message.message_type_name:
            self.notification_count += 1

    def to_dict(self) -> dict[str, Any]:
        latencies = self._latencies
        return {
            "message_count": self.message_count,
            "request_count": self.request_count,
            "response_count": self.response_count,
            "notification_count": self.notification_count,
            "unmatched_requests_observed": len(self._pending),
            "unmatched_responses_observed": self.unmatched_responses,
            "correlation_capacity_exceeded": self.pending_overflow,
            "average_response_latency_seconds": (
                sum(latencies) / len(latencies) if latencies else None
            ),
            "maximum_response_latency_seconds": max(latencies) if latencies else None,
            "examples": self.examples,
        }
