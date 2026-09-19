"""Small, dependency-free Ethernet/IP/transport parser for BLF frame bytes."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class TransportPayload:
    source_mac: str
    destination_mac: str
    ether_type: int
    vlan_ids: tuple[int, ...]
    network_protocol: str
    source_ip: str
    destination_ip: str
    transport: str
    source_port: int
    destination_port: int
    payload: bytes


def _mac(value: bytes) -> str:
    return ":".join(f"{part:02x}" for part in value)


def parse_ethernet_frame(frame: bytes) -> Optional[TransportPayload]:
    """Extract a UDP/TCP payload from Ethernet II + IPv4/IPv6, if present."""

    if len(frame) < 14:
        return None
    destination_mac = _mac(frame[0:6])
    source_mac = _mac(frame[6:12])
    ether_type = int.from_bytes(frame[12:14], "big")
    offset = 14
    vlan_ids: list[int] = []
    while ether_type in {0x8100, 0x88A8}:
        if len(frame) < offset + 4:
            return None
        vlan_ids.append(int.from_bytes(frame[offset : offset + 2], "big") & 0x0FFF)
        ether_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
        offset += 4

    if ether_type == 0x0800:
        parsed = _parse_ipv4(frame, offset)
    elif ether_type == 0x86DD:
        parsed = _parse_ipv6(frame, offset)
    else:
        return None
    if parsed is None:
        return None

    network_protocol, source_ip, destination_ip, transport, src_port, dst_port, payload = parsed
    return TransportPayload(
        source_mac=source_mac,
        destination_mac=destination_mac,
        ether_type=ether_type,
        vlan_ids=tuple(vlan_ids),
        network_protocol=network_protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        transport=transport,
        source_port=src_port,
        destination_port=dst_port,
        payload=payload,
    )


def classify_ether_type(frame: bytes) -> tuple[str, Optional[int], tuple[int, ...]]:
    """Classify Ethernet II without retaining its payload."""

    if len(frame) < 14:
        return "truncated", None, ()
    ether_type = int.from_bytes(frame[12:14], "big")
    offset = 14
    vlans: list[int] = []
    while ether_type in {0x8100, 0x88A8} and len(frame) >= offset + 4:
        vlans.append(int.from_bytes(frame[offset : offset + 2], "big") & 0x0FFF)
        ether_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
        offset += 4
    names = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP"}
    return names.get(ether_type, f"EtherType 0x{ether_type:04X}"), ether_type, tuple(vlans)


def _parse_ipv4(frame: bytes, offset: int):
    if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        return None
    header_length = (frame[offset] & 0x0F) * 4
    total_length = int.from_bytes(frame[offset + 2 : offset + 4], "big")
    if header_length < 20 or total_length < header_length or len(frame) < offset + total_length:
        return None
    protocol = frame[offset + 9]
    source_ip = str(ipaddress.ip_address(frame[offset + 12 : offset + 16]))
    destination_ip = str(ipaddress.ip_address(frame[offset + 16 : offset + 20]))
    return _parse_transport(
        frame[offset + header_length : offset + total_length],
        protocol,
        "IPv4",
        source_ip,
        destination_ip,
    )


def _parse_ipv6(frame: bytes, offset: int):
    if len(frame) < offset + 40 or frame[offset] >> 4 != 6:
        return None
    payload_length = int.from_bytes(frame[offset + 4 : offset + 6], "big")
    if len(frame) < offset + 40 + payload_length:
        return None
    next_header = frame[offset + 6]
    source_ip = str(ipaddress.ip_address(frame[offset + 8 : offset + 24]))
    destination_ip = str(ipaddress.ip_address(frame[offset + 24 : offset + 40]))
    return _parse_transport(
        frame[offset + 40 : offset + 40 + payload_length],
        next_header,
        "IPv6",
        source_ip,
        destination_ip,
    )


def _parse_transport(
    segment: bytes, protocol: int, network: str, source_ip: str, destination_ip: str
):
    if protocol == 17:
        if len(segment) < 8:
            return None
        source_port = int.from_bytes(segment[0:2], "big")
        destination_port = int.from_bytes(segment[2:4], "big")
        length = int.from_bytes(segment[4:6], "big")
        if length < 8 or length > len(segment):
            return None
        return network, source_ip, destination_ip, "UDP", source_port, destination_port, segment[8:length]
    if protocol == 6:
        if len(segment) < 20:
            return None
        source_port = int.from_bytes(segment[0:2], "big")
        destination_port = int.from_bytes(segment[2:4], "big")
        header_length = (segment[12] >> 4) * 4
        if header_length < 20 or header_length > len(segment):
            return None
        return network, source_ip, destination_ip, "TCP", source_port, destination_port, segment[header_length:]
    return None
