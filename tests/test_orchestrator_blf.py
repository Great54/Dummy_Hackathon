import tempfile
import unittest
from pathlib import Path

from vblf.can import CanMessage
from vblf.constants import ObjFlags
from vblf.writer import BlfWriter

from app.orchestrator.evidence import AnalysisResult
from app.orchestrator.orchestrator import AnalysisOrchestrator
from input.models import AnalysisRequest


class StubAgent:
    def analyze(self, request, evidence):
        return AnalysisResult(
            root_cause="Not determined by stub agent.",
            recommendation="Continue investigation.",
            evidence=evidence,
        )


class OrchestratorBlfTests(unittest.TestCase):
    def test_no_blf_skips_tool(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            result = AnalysisOrchestrator(StubAgent()).run(
                AnalysisRequest(repo, "Defect without a log")
            )
        self.assertEqual([item.source for item in result.evidence], ["Repository Analysis"])
        self.assertFalse(result.evidence[0].details["evidence_found"])

    def test_blf_is_discovered_and_evidence_reaches_agent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.blf"
            with BlfWriter(path) as writer:
                writer.write(
                    CanMessage.new(
                        ObjFlags.TIME_ONE_NANS,
                        0,
                        1,
                        0,
                        8,
                        0x123,
                        bytes(8),
                    )
                )
            result = AnalysisOrchestrator(StubAgent()).run(
                AnalysisRequest(directory, "CAN defect", blf_path=str(path))
            )

        blf_evidence = next(item for item in result.evidence if item.source.startswith("BLF"))
        self.assertEqual(blf_evidence.details["can_message_count"], 1)


if __name__ == "__main__":
    unittest.main()