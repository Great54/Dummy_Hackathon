import tempfile
import unittest
from pathlib import Path

from app.tools.repository_inventory_tool import (
    RepositoryInventoryTool,
    detect_question_intent,
)
from input.models import AnalysisRequest


class RepositoryInventoryToolTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.tool = RepositoryInventoryTool()

    def tearDown(self):
        self.tempdir.cleanup()

    def write(self, relative_path: str, content: str) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_count_unique_pdu_definitions(self):
        self.write(
            "system/ecu.arxml",
            """
            <AUTOSAR>
              <AR-PACKAGES>
                <AR-PACKAGE>
                  <ELEMENTS>
                    <I-SIGNAL-I-PDU>
                      <SHORT-NAME>EnginePdu</SHORT-NAME>
                    </I-SIGNAL-I-PDU>
                    <N-PDU>
                      <SHORT-NAME>NmPdu</SHORT-NAME>
                    </N-PDU>
                    <I-SIGNAL-I-PDU>
                      <SHORT-NAME>EnginePdu</SHORT-NAME>
                    </I-SIGNAL-I-PDU>
                  </ELEMENTS>
                </AR-PACKAGE>
              </AR-PACKAGES>
            </AUTOSAR>
            """,
        )

        evidence = self.tool.run(AnalysisRequest(str(self.root), "How many PDUs are present in the project?"))

        self.assertEqual(evidence.details["total_unique_pdu_definitions"], 2)
        self.assertEqual(evidence.details["type_breakdown"]["I-SIGNAL-I-PDU"], 1)
        self.assertEqual(evidence.details["type_breakdown"]["N-PDU"], 1)
        self.assertEqual(len(evidence.details["duplicate_definitions"]), 1)

    def test_namespace_and_multiple_files_are_handled(self):
        self.write(
            "config/one.arxml",
            """
            <ns:AUTOSAR xmlns:ns="http://autosar.org/schema">
              <ns:AR-PACKAGES>
                <ns:AR-PACKAGE>
                  <ns:ELEMENTS>
                    <ns:I-SIGNAL-I-PDU>
                      <ns:SHORT-NAME>FirstPdu</ns:SHORT-NAME>
                    </ns:I-SIGNAL-I-PDU>
                  </ns:ELEMENTS>
                </ns:AR-PACKAGE>
              </ns:AR-PACKAGES>
            </ns:AUTOSAR>
            """,
        )
        self.write(
            "config/two.arxml",
            """
            <AUTOSAR>
              <AR-PACKAGES>
                <AR-PACKAGE>
                  <ELEMENTS>
                    <CAN-PDU>
                      <SHORT-NAME>CanPdu</SHORT-NAME>
                    </CAN-PDU>
                  </ELEMENTS>
                </AR-PACKAGE>
              </AR-PACKAGES>
            </AUTOSAR>
            """,
        )

        evidence = self.tool.run(AnalysisRequest(str(self.root), "How many CAN PDUs are present?"))

        self.assertEqual(evidence.details["total_unique_pdu_definitions"], 2)
        self.assertEqual(evidence.details["files_inspected"], 2)
        self.assertIn("FirstPdu", {item["name"] for item in evidence.details["definitions"]})

    def test_definition_is_not_counted_as_reference(self):
        self.write(
            "system/refs.arxml",
            """
            <AUTOSAR>
              <AR-PACKAGES>
                <AR-PACKAGE>
                  <ELEMENTS>
                    <I-SIGNAL-I-PDU>
                      <SHORT-NAME>ActualPdu</SHORT-NAME>
                    </I-SIGNAL-I-PDU>
                    <PDU-REF>
                      <PDU-REF>ActualPdu</PDU-REF>
                    </PDU-REF>
                  </ELEMENTS>
                </AR-PACKAGE>
              </AR-PACKAGES>
            </AUTOSAR>
            """,
        )

        evidence = self.tool.run(AnalysisRequest(str(self.root), "List all configured PDUs."))
        self.assertEqual(evidence.details["total_unique_pdu_definitions"], 1)
        self.assertEqual(evidence.details["references_skipped"], 1)

    def test_duplicate_definitions_are_reported(self):
        self.write(
            "a/arxml.xml",
            """
            <AUTOSAR><AR-PACKAGES><AR-PACKAGE><ELEMENTS><I-SIGNAL-I-PDU><SHORT-NAME>DupPdu</SHORT-NAME></I-SIGNAL-I-PDU></ELEMENTS></AR-PACKAGE></AR-PACKAGES></AUTOSAR>
            """,
        )
        self.write(
            "b/other.xml",
            """
            <AUTOSAR><AR-PACKAGES><AR-PACKAGE><ELEMENTS><I-SIGNAL-I-PDU><SHORT-NAME>DupPdu</SHORT-NAME></I-SIGNAL-I-PDU></ELEMENTS></AR-PACKAGE></AR-PACKAGES></AUTOSAR>
            """,
        )

        evidence = self.tool.run(AnalysisRequest(str(self.root), "How many PDUs are present in the project?"))
        self.assertEqual(evidence.details["duplicate_definitions"][0]["name"], "DupPdu")

    def test_malformed_xml_is_reported_without_crashing(self):
        self.write("broken/arxml.xml", "<AUTOSAR><BROKEN>")

        evidence = self.tool.run(AnalysisRequest(str(self.root), "How many PDUs are present in the project?"))
        self.assertIn("malformed_files", evidence.details)
        self.assertEqual(evidence.details["total_unique_pdu_definitions"], 0)

    def test_empty_repository_returns_no_pdu_definitions(self):
        evidence = self.tool.run(AnalysisRequest(str(self.root), "How many PDUs are present in the project?"))
        self.assertEqual(evidence.details["total_unique_pdu_definitions"], 0)
        self.assertEqual(evidence.details["definitions"], [])

    def test_question_intent_detection(self):
        self.assertEqual(detect_question_intent("How many PDUs are present in the project?"), "repository_inventory")
        self.assertEqual(detect_question_intent("Where is ComIPdu configured?"), "repository_search")
        self.assertEqual(detect_question_intent("Why does the PDU transmission fail?"), "defect_log_analysis")
        self.assertEqual(detect_question_intent("Which AUTOSAR requirement governs E2E counter handling?"), "autosar_requirement_lookup")

    def test_distinct_questions_stay_on_distinct_routes(self):
      controlled_questions = {
        "How many PDUs are present in the project?": "repository_inventory",
        "What does the RepositoryTool do?": "mixed_investigation",
        "Where is vlanmonenable used?": "repository_search",
        "Why does SensorStatus become UNAVAILABLE?": "defect_log_analysis",
        "Which AUTOSAR requirement applies to E2E counter handling?": "autosar_requirement_lookup",
      }

      for question, expected in controlled_questions.items():
        with self.subTest(question=question):
          self.assertEqual(detect_question_intent(question), expected)


if __name__ == "__main__":
    unittest.main()
