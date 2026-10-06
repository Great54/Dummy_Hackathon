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
            evidence=[
                Evidence("TTL Analysis", "Found relevant definition", {}),
                Evidence(
                    "AUTOSAR Official Specification",
                    "No matching AUTOSAR requirement identified",
                    {"status": "no_match", "requirements": []},
                    severity="warning",
                ),
            ],
            confidence="medium",
            hypotheses=["Interface version mismatch."],
            next_investigation_steps=["Capture SOME/IP traffic."],
            correlation="AUTOSAR lookup found no matching requirement.",
        )

        window._render_result(result)
        rendered = window.result_edit.toPlainText()

        self.assertIn("AI ANALYSIS", rendered)
        self.assertIn("Root Cause", rendered)
        self.assertIn("Likely configuration mismatch.", rendered)
        self.assertIn("MEDIUM", rendered)
        self.assertIn("TTL Analysis", rendered)
        self.assertIn("Log Evidence", rendered)
        self.assertIn("Repository Evidence", rendered)
        self.assertIn("AUTOSAR Requirements", rendered)
        self.assertIn("No matching AUTOSAR requirement identified", rendered)
        self.assertIn("Correlation", rendered)
        self.assertIn("AUTOSAR lookup found no matching requirement", rendered)
        self.assertTrue(window.result_edit.openExternalLinks())
        self.assertIn("Compare service definitions.", rendered)
        self.assertIn("Capture SOME/IP traffic.", rendered)
        window.close()

    def test_official_autosar_requirement_renders_source_link(self):
        evidence = Evidence(
            "AUTOSAR Official Specification",
            "Relevant requirement identified.",
            {
                "status": "matched",
                "release": "R25-11",
                "lookup_complete": False,
                "requirements": [
                    {
                        "requirement_id": "SRS_Com_02089",
                        "document": "Requirements on Communication",
                        "release": "R25-11",
                        "platform": "CP",
                        "applicability": "DIRECTLY APPLICABLE",
                        "requirement_summary": "Official short excerpt.",
                        "relevance_reason": "Signal timeout evidence matches.",
                        "confidence": 0.9,
                        "source_url": "https://www.autosar.org/fileadmin/standards/R25-11/CP/AUTOSAR_CP_RS_COM.pdf",
                    }
                ],
            },
        )

        rendered = LogAnalyzerWindow._render_autosar_evidence([evidence])

        self.assertIn("SRS_Com_02089", rendered)
        self.assertIn("additional matching documents may not have been inspected", rendered)
        self.assertIn(
            "href='https://www.autosar.org/fileadmin/standards/R25-11/CP/AUTOSAR_CP_RS_COM.pdf'",
            rendered,
        )


if __name__ == "__main__":
    unittest.main()
