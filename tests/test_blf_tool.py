import tempfile
import unittest
from pathlib import Path

from vblf.can import CanFdMessage, CanMessage
from vblf.constants import CanFdFlags, ObjFlags
from vblf.writer import BlfWriter

from app.tools.blf_tool import BlfAnalysisError, BlfTool
from input.models import AnalysisRequest


class BlfToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = BlfTool()
        self.repo = tempfile.TemporaryDirectory()
        self.request_base = {
            "repo_path": self.repo.name,
            "defect_description": "CAN message intermittently missing",
        }

    def tearDown(self) -> None:
        self.repo.cleanup()

    def test_not_applicable_without_blf(self) -> None:
        request = AnalysisRequest(**self.request_base)
        self.assertFalse(self.tool.is_applicable(request))

    def test_applicable_with_blf_path(self) -> None:
        request = AnalysisRequest(**self.request_base, blf_path="capture.blf")
        self.assertTrue(self.tool.is_applicable(request))

    def test_missing_file_is_controlled_error(self) -> None:
        request = AnalysisRequest(**self.request_base, blf_path="missing.blf")
        with self.assertRaisesRegex(BlfAnalysisError, "does not exist"):
            self.tool.run(request)

    def test_wrong_extension_is_controlled_error(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".txt") as file:
            request = AnalysisRequest(**self.request_base, blf_path=file.name)
            with self.assertRaisesRegex(BlfAnalysisError, "not a .blf"):
                self.tool.run(request)

    def test_small_real_can_blf_returns_metadata_and_can_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "small.blf"
            with BlfWriter(path) as writer:
                writer.write(self._message(1, 0x123, 0))
                writer.write(self._message(1, 0x123, 1_000_000))
                writer.write(self._message(2, 0x456, 2_000_000))

            evidence = self.tool.run(
                AnalysisRequest(**self.request_base, blf_path=str(path))
            )

        self.assertEqual(evidence.source, "BLF / CAN and Ethernet Analysis")
        self.assertEqual(evidence.details["can_message_count"], 3)
        self.assertEqual(evidence.details["can_fd_message_count"], 0)
        self.assertEqual(evidence.details["channels"], [1, 2])
        self.assertEqual(evidence.details["duration_seconds"], 0.002)
        self.assertEqual(evidence.details["top_can_ids"][0]["can_id"], "0x123")
        self.assertEqual(evidence.details["top_can_ids"][0]["count"], 2)

    def test_evidence_examples_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bounded.blf"
            with BlfWriter(path) as writer:
                for index in range(100):
                    writer.write(self._message(1, index, index * 1_000))

            evidence = self.tool.run(
                AnalysisRequest(**self.request_base, blf_path=str(path))
            )

        self.assertLessEqual(len(evidence.details["can_examples"]), 20)
        self.assertLessEqual(len(evidence.details["top_can_ids"]), 20)
        self.assertNotIn("messages", evidence.details)

    def test_can_fd_blf_returns_can_fd_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "can_fd.blf"
            with BlfWriter(path) as writer:
                writer.write(
                    CanFdMessage.new(
                        object_flags=ObjFlags.TIME_ONE_NANS,
                        object_time_stamp=1000,
                        channel=3,
                        flags=0,
                        dlc=15,
                        frame_id=0x789,
                        frame_length=1000,
                        arb_bit_count=20,
                        canfd_flags=CanFdFlags(0),
                        data=bytes(range(64)),
                    )
                )

            evidence = self.tool.run(
                AnalysisRequest(**self.request_base, blf_path=str(path))
            )

        self.assertEqual(evidence.details["can_fd_message_count"], 1)
        self.assertEqual(evidence.details["top_can_ids"][0]["payload_length"], 64)
        self.assertTrue(evidence.details["top_can_ids"][0]["can_fd"])

    @staticmethod
    def _message(channel: int, frame_id: int, timestamp: int) -> CanMessage:
        return CanMessage.new(
            object_flags=ObjFlags.TIME_ONE_NANS,
            object_time_stamp=timestamp,
            channel=channel,
            flags=0,
            dlc=8,
            frame_id=frame_id,
            data=bytes(range(8)),
        )


if __name__ == "__main__":
    unittest.main()
