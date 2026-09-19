import ipaddress
import struct
import unittest

from app.tools.protocols.ethernet_parser import parse_ethernet_frame
from app.tools.protocols.someip_parser import parse_someip
from app.tools.protocols.someip_sd_parser import parse_someip_sd


def someip_message(
    message_id: int = 0x12340001,
    request_id: int = 0x002A0007,
    message_type: int = 0x00,
    payload: bytes = b"abc",
) -> bytes:
    length = 8 + len(payload)
    trailer = (1 << 24) | (2 << 16) | (message_type << 8)
    return struct.pack("!IIII", message_id, length, request_id, trailer) + payload


def ethernet_ipv4_udp(payload: bytes, destination_port: int = 30500) -> bytes:
    udp = struct.pack("!HHHH", 30499, destination_port, 8 + len(payload), 0) + payload
    source = ipaddress.ip_address("192.0.2.1").packed
    destination = ipaddress.ip_address("192.0.2.2").packed
    total_length = 20 + len(udp)
    ipv4 = (
        bytes([0x45, 0])
        + total_length.to_bytes(2, "big")
        + bytes(4)
        + bytes([64, 17])
        + bytes(2)
        + source
        + destination
        + udp
    )
    return bytes.fromhex("00112233445566778899aabb0800") + ipv4


class ProtocolParserTests(unittest.TestCase):
    def test_someip_fields_are_extracted_from_ethernet_udp(self) -> None:
        transport = parse_ethernet_frame(ethernet_ipv4_udp(someip_message()))
        self.assertIsNotNone(transport)
        message = parse_someip(transport.payload)
        self.assertIsNotNone(message)
        self.assertEqual(message.service_id, 0x1234)
        self.assertEqual(message.method_id, 1)
        self.assertEqual(message.client_id, 0x002A)
        self.assertEqual(message.session_id, 7)
        self.assertEqual(message.message_type_name, "request")

    def test_someip_sd_offer_is_extracted(self) -> None:
        entry = (
            bytes([0x01, 0, 0, 0])
            + struct.pack("!HH", 0x1234, 0x0001)
            + bytes([2])
            + (10).to_bytes(3, "big")
            + (5).to_bytes(4, "big")
        )
        sd_payload = bytes([0xC0, 0, 0, 0]) + len(entry).to_bytes(4, "big") + entry + bytes(4)
        message = parse_someip(someip_message(0xFFFF8100, payload=sd_payload))
        result = parse_someip_sd(message)
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries"][0]["entry_type"], "OfferService")
        self.assertEqual(result["entries"][0]["service_id"], "0x1234")
        self.assertEqual(result["entries"][0]["ttl_seconds"], 10)

    def test_unrelated_udp_is_not_classified_as_someip(self) -> None:
        transport = parse_ethernet_frame(ethernet_ipv4_udp(b"not someip"))
        self.assertIsNotNone(transport)
        self.assertIsNone(parse_someip(transport.payload))

    def test_invalid_someip_length_is_rejected(self) -> None:
        malformed = struct.pack("!IIII", 0x12340001, 1000, 1, 0x01010000)
        self.assertIsNone(parse_someip(malformed))


if __name__ == "__main__":
    unittest.main()
