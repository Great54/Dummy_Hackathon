import tempfile
import unittest
from pathlib import Path

from app.tools.repository_inventory_tool import detect_question_intent
from app.tools.someip_inventory_tool import SomeIpInventoryTool
from input.models import AnalysisRequest


class SomeIpInventoryToolTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()

    def tearDown(self):
        self.tempdir.cleanup()

    def write(self, relative_path: str, content: str) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_someip_question_is_classified_and_counted(self):
        self.write(
            "config/services.arxml",
            """
            <AUTOSAR>
              <AR-PACKAGES>
                <AR-PACKAGE>
                  <ELEMENTS>
                    <SERVICE-INTERFACE>
                      <SHORT-NAME>VehicleService</SHORT-NAME>
                      <SERVICE-IDENTIFIER>0x1234</SERVICE-IDENTIFIER>
                    </SERVICE-INTERFACE>
                    <SERVICE-INTERFACE>
                      <SHORT-NAME>VehicleService</SHORT-NAME>
                      <SERVICE-IDENTIFIER>0x1234</SERVICE-IDENTIFIER>
                    </SERVICE-INTERFACE>
                    <SERVICE-INTERFACE>
                      <SHORT-NAME>StatusService</SHORT-NAME>
                      <SERVICE-IDENTIFIER>0x5678</SERVICE-IDENTIFIER>
                    </SERVICE-INTERFACE>
                  </ELEMENTS>
                </AR-PACKAGE>
              </AR-PACKAGES>
            </AUTOSAR>
            """,
        )
        self.write(
            "config/deployments.arxml",
            """
            <AUTOSAR>
              <AR-PACKAGES>
                <AR-PACKAGE>
                  <ELEMENTS>
                    <SERVICE-INSTANCE>
                      <SHORT-NAME>VehicleProvided</SHORT-NAME>
                      <SERVICE-INSTANCE-ID>1</SERVICE-INSTANCE-ID>
                      <SERVICE-REF>VehicleService</SERVICE-REF>
                      <PROVIDED>true</PROVIDED>
                    </SERVICE-INSTANCE>
                    <SERVICE-INSTANCE>
                      <SHORT-NAME>VehicleRequired</SHORT-NAME>
                      <SERVICE-INSTANCE-ID>2</SERVICE-INSTANCE-ID>
                      <SERVICE-REF>VehicleService</SERVICE-REF>
                      <PROVIDED>false</PROVIDED>
                    </SERVICE-INSTANCE>
                  </ELEMENTS>
                </AR-PACKAGE>
              </AR-PACKAGES>
            </AUTOSAR>
            """,
        )

        self.assertEqual(
            detect_question_intent("How many SOME/IP services are present in the project?"),
            "someip_inventory",
        )

        evidence = SomeIpInventoryTool().run(
            AnalysisRequest(str(self.root), "How many SOME/IP services are present in the project?")
        )

        self.assertEqual(evidence.details["unique_service_interfaces"], 2)
        self.assertEqual(evidence.details["unique_service_ids"], 2)
        self.assertEqual(evidence.details["provided_service_instances"], 1)
        self.assertEqual(evidence.details["required_service_instances"], 1)


if __name__ == "__main__":
    unittest.main()
