import tempfile
import unittest
from pathlib import Path

from input.handler import create_analysis_request


class AnalysisRequestValidationTests(unittest.TestCase):
    def test_repository_and_defect_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Repository path does not exist"):
                create_analysis_request(str(Path(directory) / "missing"), "Defect")
            with self.assertRaisesRegex(ValueError, "cannot be empty"):
                create_analysis_request(directory, "  ")

    def test_log_inputs_remain_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            request = create_analysis_request(directory, "Defect")

        self.assertIsNone(request.blf_path)
        self.assertIsNone(request.mf4_path)
        self.assertIsNone(request.pcapng_path)
        self.assertIsNone(request.ttl_path)

    def test_supported_log_extensions_are_accepted_case_insensitively(self):
        extensions = {
            "blf": "capture.BLF",
            "mf4": "capture.MF4",
            "pcapng": "capture.PCAPNG",
            "ttl": "capture.TTL",
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for file_type, name in extensions.items():
                path = Path(directory) / name
                path.write_bytes(b"fixture")
                paths[file_type] = str(path)

            request = create_analysis_request(
                directory,
                "Defect",
                blf_path=paths["blf"],
                mf4_path=paths["mf4"],
                pcapng_path=paths["pcapng"],
                ttl_path=paths["ttl"],
            )

        self.assertTrue(request.blf_path.endswith("capture.BLF"))
        self.assertTrue(request.mf4_path.endswith("capture.MF4"))
        self.assertTrue(request.pcapng_path.endswith("capture.PCAPNG"))
        self.assertTrue(request.ttl_path.endswith("capture.TTL"))

    def test_rejects_unsupported_extension_for_selected_log_type(self):
        with tempfile.TemporaryDirectory() as directory:
            unsupported = Path(directory) / "capture.txt"
            unsupported.write_text("not a BLF", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "must use the .blf extension"):
                create_analysis_request(
                    directory, "Defect", blf_path=str(unsupported)
                )


if __name__ == "__main__":
    unittest.main()