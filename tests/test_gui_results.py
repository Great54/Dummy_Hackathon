import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from app.gui import LogAnalyzerWindow
from app.orchestrator.evidence import AnalysisResult, Evidence


class GuiResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_analysis_result_is_rendered_in_dedicated_section(self) -> None:
        window = LogAnalyzerWindow()
        result = AnalysisResult(
            root_cause="Likely configuration mismatch.",
            recommendation="Compare service definitions.",
            evidence=[Evidence("TTL Analysis", "Found relevant definition", {})],
            confidence="medium",
            hypotheses=["Interface version mismatch."],
            next_investigation_steps=["Capture SOME/IP traffic."],
        )

        window._render_result(result)
        rendered = window.result_edit.toPlainText()

        self.assertIn("AI ANALYSIS", rendered)
        self.assertIn("Root Cause", rendered)
        self.assertIn("Likely configuration mismatch.", rendered)
        self.assertIn("MEDIUM", rendered)
        self.assertIn("TTL Analysis", rendered)
        self.assertIn("Compare service definitions.", rendered)
        self.assertIn("Capture SOME/IP traffic.", rendered)
        window.close()


if __name__ == "__main__":
    unittest.main()
