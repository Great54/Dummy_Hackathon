import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app.agent.reasoning_agent import ReasoningAgent
from app.orchestrator.orchestrator import AnalysisOrchestrator
from app.tools import registry
from app.tools.ttl_trace_tool import (
    FIELD_NAMES,
    MAX_EXAMPLES,
    TtlTraceAnalysisError,
    TtlTraceTool,
)
from input.models import AnalysisRequest


class FakeProcess:
    def __init__(self, lines, stderr="", return_code=0):
        self.stdout = io.StringIO("".join(lines))
        self.stderr = io.StringIO(stderr)
        self.return_code = return_code
        self.terminated = False

    def poll(self):
        return self.return_code if self.terminated else None

    def wait(self, timeout=None):
        return self.return_code

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True


class FakeGeminiClient:
    def __init__(self):
        self.prompts = []

    def generate_json(self, prompt):
        self.prompts.append(prompt)
        return json.dumps(
            {
                "root_cause": "TTL evidence indicates a possible service issue.",
                "recommendation": "Inspect the captured SOME/IP exchange.",
                "confidence": "medium",
                "hypotheses": [],
                "next_investigation_steps": ["Compare requests and responses."],
            }
        )


def make_row(**values):
    row = [values.get(field, "") for field in FIELD_NAMES]
    output = io.StringIO()
    import csv

    writer = csv.writer(output, delimiter="\t", quotechar='"', lineterminator="\n")
    writer.writerow(row)
    return output.getvalue()


def write_tttech_fixture(path):
    path.write_bytes(
        b"TTL "
        + (10).to_bytes(4, "little")
        + (2_097_152).to_bytes(4, "little")
        + (16).to_bytes(4, "little")
    )


class TtlTraceToolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "trace.ttl"
        write_tttech_fixture(self.path)
        self.request = AnalysisRequest(
            self.directory.name,
            "SOME/IP response is not received",
            ttl_path=str(self.path),
        )

    def tearDown(self):
        self.directory.cleanup()

    def _run_tool(self, lines, stderr=""):
        process = FakeProcess(lines, stderr)
        tool = TtlTraceTool(popen_factory=lambda *args, **kwargs: process)
        with patch("app.tools.ttl_trace_tool.find_tshark", return_value="tshark"), patch(
            "app.tools.ttl_trace_tool._tshark_version", return_value="4.6.7"
        ):
            return tool.run(self.request)

    def test_binary_ttl_selects_trace_tool_not_text_tool(self):
        names = [tool.name for tool in registry.get_applicable_tools(self.request)]
        self.assertEqual(names, ["TTTech TTL Analysis", "Repository Analysis"])

    def test_mocked_tshark_output_produces_bounded_evidence(self):
        lines = [
            make_row(
                **{
                    "frame.number": "1",
                    "frame.time_epoch": "100.0",
                    "frame.interface_name": "Ethernet A",
                    "_ws.col.Protocol": "SOME/IP",
                    "_ws.col.Info": "Request",
                    "eth.src": "00:11:22:33:44:55",
                    "eth.dst": "66:77:88:99:aa:bb",
                    "ip.src": "192.0.2.1",
                    "ip.dst": "192.0.2.2",
                    "udp.srcport": "30490",
                    "udp.dstport": "30500",
                    "someip.serviceid": "0x1234",
                    "someip.methodid": "0x0001",
                    "someip.clientid": "0x0010",
                    "someip.sessionid": "0x0020",
                    "someip.messagetype": "0x00",
                    "someip.returncode": "0x00",
                }
            ),
            make_row(
                **{
                    "frame.number": "2",
                    "frame.time_epoch": "100.25",
                    "frame.interface_name": "CAN 1",
                    "_ws.col.Protocol": "CANFD",
                    "_ws.col.Info": "ID 0x123",
                    "can.id": "0x00000123",
                    "can.len": "64",
                    "canfd.flags.fdf": "1",
                }
            ),
            make_row(
                **{
                    "frame.number": "3",
                    "frame.time_epoch": "100.5",
                    "frame.interface_name": "Ethernet A",
                    "_ws.col.Protocol": "SOME/IP-SD",
                    "someipsd.entry.type": "0x01",
                    "someipsd.entry.serviceid": "0x1234",
                    "someipsd.entry.instanceid": "0x0001",
                    "someipsd.entry.ttl": "3",
                }
            ),
        ]

        evidence = self._run_tool(lines)
        details = evidence.details

        self.assertEqual(evidence.source, "TTTech TTL / TShark Analysis")
        self.assertEqual(details["records_processed"], 3)
        self.assertEqual(details["someip_message_count"], 1)
        self.assertEqual(details["someip_sd_entry_count"], 1)
        self.assertEqual(details["can_fd_frame_count"], 1)
        self.assertEqual(details["capture_duration_seconds"], 0.5)
        self.assertLessEqual(len(details["record_examples"]), MAX_EXAMPLES)
        self.assertFalse(details["raw_ttl_content_returned"])
        self.assertFalse(details["converted_capture_created"])

    def test_missing_tshark_has_required_message(self):
        with patch("app.tools.ttl_trace_tool.find_tshark", return_value=None):
            with self.assertRaisesRegex(
                TtlTraceAnalysisError,
                "TTTech TTL analysis requires TShark. Please install Wireshark/TShark.",
            ):
                TtlTraceTool().run(self.request)

    def test_cancel_terminates_active_process(self):
        process = FakeProcess([])
        process.return_code = 0
        tool = TtlTraceTool()
        tool._process = process
        tool.cancel()
        self.assertTrue(process.terminated)

    def test_nonzero_tshark_exit_is_controlled(self):
        process = FakeProcess([], "tshark decode failed\n", return_code=2)
        tool = TtlTraceTool(popen_factory=lambda *args, **kwargs: process)
        with patch("app.tools.ttl_trace_tool.find_tshark", return_value="tshark"), patch(
            "app.tools.ttl_trace_tool._tshark_version", return_value="4.6.7"
        ):
            with self.assertRaisesRegex(TtlTraceAnalysisError, "decode failed"):
                tool.run(self.request)

    def test_timeout_terminates_tshark(self):
        process = FakeProcess([])
        tool = TtlTraceTool(popen_factory=lambda *args, **kwargs: process)
        with patch("app.tools.ttl_trace_tool.find_tshark", return_value="tshark"), patch(
            "app.tools.ttl_trace_tool._tshark_version", return_value="4.6.7"
        ), patch("app.tools.ttl_trace_tool.time.monotonic", side_effect=[0.0, 301.0]):
            with self.assertRaisesRegex(TtlTraceAnalysisError, "timeout"):
                tool.run(self.request)
        self.assertTrue(process.terminated)

    def test_trace_evidence_reaches_orchestrator_and_reasoning_agent(self):
        process = FakeProcess(
            [
                make_row(
                    **{
                        "frame.number": "1",
                        "frame.time_epoch": "100.0",
                        "frame.interface_name": "Ethernet A",
                        "_ws.col.Protocol": "SOME/IP",
                        "someip.serviceid": "0x1234",
                        "someip.methodid": "0x0001",
                    }
                )
            ]
        )
        trace_tool = next(
            tool for tool in registry.get_registered_tools() if tool.name == "TTTech TTL Analysis"
        )
        old_factory = trace_tool._popen_factory
        trace_tool._popen_factory = lambda *args, **kwargs: process
        client = FakeGeminiClient()
        try:
            with patch("app.tools.ttl_trace_tool.find_tshark", return_value="tshark"), patch(
                "app.tools.ttl_trace_tool._tshark_version", return_value="4.6.7"
            ):
                result = AnalysisOrchestrator(ReasoningAgent(client)).run(self.request)
        finally:
            trace_tool._popen_factory = old_factory

        self.assertEqual(result.evidence[0].source, "TTTech TTL / TShark Analysis")
        self.assertIn("0x1234", client.prompts[0])
        self.assertEqual(result.confidence, "medium")


if __name__ == "__main__":
    unittest.main()
