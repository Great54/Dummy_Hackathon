import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.orchestrator.evidence import AnalysisResult
from app.orchestrator.orchestrator import AnalysisOrchestrator
from app.tools.registry import get_registered_tools
from app.tools.ttl_tool import MAX_RELEVANT_MATCHES, TtlAnalysisError, TtlTool
from input.models import AnalysisRequest


TTL_CONTENT = """@prefix ex: <http://example.test/vehicle#> .
@prefix someip: <http://example.test/someip#> .

ex:VehicleService a someip:Service ;
    someip:serviceId "0x1234" ;
    someip:transport "UDP" .

ex:StatusEvent a someip:Event ;
    someip:methodId "0x8001" ;
    ex:signal ex:VehicleStatusSignal .

ex:VehicleStatusSignal a ex:Signal ;
    ex:unit "km/h" .

ex:UnrelatedNode a ex:DataType .
"""


class TtlToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = TtlTool()
        self.repo = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.repo.cleanup()

    def _request(self, ttl_path=None, defect="SOME/IP service event missing over UDP"):
        return AnalysisRequest(
            repo_path=self.repo.name,
            defect_description=defect,
            ttl_path=ttl_path,
        )

    def test_tool_is_registered(self) -> None:
        self.assertIn("TTL Analysis", [tool.name for tool in get_registered_tools()])

    def test_not_applicable_without_ttl(self) -> None:
        self.assertFalse(self.tool.is_applicable(self._request()))

    def test_applicable_with_ttl_path(self) -> None:
        self.assertTrue(self.tool.is_applicable(self._request("definitions.ttl")))

    def test_missing_file_is_controlled_error(self) -> None:
        with self.assertRaisesRegex(TtlAnalysisError, "does not exist"):
            self.tool.run(self._request("missing.ttl"))

    def test_binary_tttech_trace_is_rejected_before_text_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.ttl"
            path.write_bytes(b"TTL \x00\x01binary trace data" + bytes(1024))

            with patch.object(
                self.tool,
                "_scan",
                side_effect=AssertionError("binary trace reached text scan"),
            ):
                with self.assertRaisesRegex(TtlAnalysisError, "TTTech trace"):
                    self.tool.run(self._request(str(path)))

    def test_definitions_prefixes_and_relevant_lines_are_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vehicle.ttl"
            path.write_text(TTL_CONTENT, encoding="utf-8")
            evidence = self.tool.run(self._request(str(path)))

        details = evidence.details
        self.assertEqual(evidence.source, "TTL Analysis")
        self.assertEqual(details["prefix_count"], 2)
        self.assertIn("http://example.test/someip#", details["namespaces"])
        self.assertGreaterEqual(details["definition_count"], 4)
        self.assertGreater(details["definition_counts_by_category"]["service_definitions"], 0)
        self.assertTrue(details["relevant_matches"])
        self.assertTrue(all("line" in match for match in details["relevant_matches"]))
        self.assertTrue(all(match["source_file"] == "vehicle.ttl" for match in details["relevant_matches"]))
        self.assertIn("some/ip", details["defect_keywords"])
        self.assertFalse(details["full_file_content_returned"])

    def test_defect_keywords_are_prioritized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vehicle.ttl"
            path.write_text(TTL_CONTENT, encoding="utf-8")
            evidence = self.tool.run(self._request(str(path), "VehicleStatusSignal missing"))

        first = evidence.details["relevant_matches"][0]
        self.assertIn("vehiclestatussignal", first["reason"].lower())
        self.assertGreaterEqual(first["score"], 10)

    def test_large_input_is_incremental_and_output_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.ttl"
            with path.open("w", encoding="utf-8") as stream:
                stream.write("@prefix ex: <http://example.test/> .\n")
                for index in range(5000):
                    stream.write(
                        f'ex:Signal{index} a ex:Signal ; '
                        'ex:comment "signal failure" .\n'
                    )

            with patch.object(Path, "read_text", side_effect=AssertionError("whole-file read")), patch.object(
                Path, "read_bytes", side_effect=AssertionError("whole-file read")
            ):
                evidence = self.tool.run(self._request(str(path), "signal failure"))

        details = evidence.details
        self.assertEqual(details["line_count"], 5001)
        self.assertLessEqual(len(details["relevant_matches"]), MAX_RELEVANT_MATCHES)
        self.assertLessEqual(len(details["selected_definitions"]), 25)
        self.assertNotIn("content", details)

    def test_ttl_evidence_reaches_reasoning_agent_through_orchestrator(self) -> None:
        class StubAgent:
            def analyze(self, request, evidence):
                return AnalysisResult("Not determined", "Investigate", evidence)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vehicle.ttl"
            path.write_text(TTL_CONTENT, encoding="utf-8")
            result = AnalysisOrchestrator(StubAgent()).run(
                AnalysisRequest(directory, "SOME/IP service missing", ttl_path=str(path))
            )

        self.assertIn("TTL Analysis", [item.source for item in result.evidence])
        self.assertIn("Repository Analysis", [item.source for item in result.evidence])


if __name__ == "__main__":
    unittest.main()
