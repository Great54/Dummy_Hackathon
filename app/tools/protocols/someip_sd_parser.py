"""Conservative SOME/IP Service Discovery entry parsing."""

from __future__ import annotations

from typing import Any

from app.tools.protocols.someip_parser import SomeIpMessage

SD_ENTRY_TYPES = {
    0x00: "FindService",
    0x01: "OfferService",
    0x06: "SubscribeEventgroup",
    0x07: "SubscribeEventgroupAck",
}
MAX_SD_ENTRIES = 50


def parse_someip_sd(message: SomeIpMessage) -> dict[str, Any]:
    """Parse bounded SD entries; endpoint options remain undecoded in Phase 2."""

    payload = message.payload
    if message.message_id != 0xFFFF8100 or len(payload) < 12:
        return {"valid": False, "entries": []}

    entries_length = int.from_bytes(payload[4:8], "big")
    entries_end = 8 + entries_length
    if entries_length % 16 or entries_end + 4 > len(payload):
        return {"valid": False, "entries": []}

    entries: list[dict[str, Any]] = []
    total_entries = entries_length // 16
    for offset in range(8, entries_end, 16):
        if len(entries) >= MAX_SD_ENTRIES:
            break
        entry = payload[offset : offset + 16]
        entry_type = entry[0]
        service_id = int.from_bytes(entry[4:6], "big")
        instance_id = int.from_bytes(entry[6:8], "big")
        major_version = entry[8]
        ttl = int.from_bytes(entry[9:12], "big")
        tail = int.from_bytes(entry[12:16], "big")
        item: dict[str, Any] = {
            "entry_type": SD_ENTRY_TYPES.get(entry_type, f"unknown_0x{entry_type:02X}"),
            "service_id": f"0x{service_id:04X}",
            "instance_id": f"0x{instance_id:04X}",
            "major_version": major_version,
            "ttl_seconds": ttl,
        }
        if entry_type in {0x00, 0x01}:
            item["minor_version"] = tail
            if entry_type == 0x01 and ttl == 0:
                item["entry_type"] = "StopOfferService"
        elif entry_type in {0x06, 0x07}:
            item["event_group_id"] = f"0x{tail & 0xFFFF:04X}"
            if entry_type == 0x07 and ttl == 0:
                item["entry_type"] = "SubscribeEventgroupNack"
        entries.append(item)

    return {
        "valid": True,
        "flags": payload[0],
        "entry_count": total_entries,
        "entries_truncated": total_entries > MAX_SD_ENTRIES,
        "entries": entries,
        "endpoint_options_decoded": False,
    }
