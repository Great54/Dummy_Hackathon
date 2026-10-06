import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

from app.orchestrator.orchestrator import AnalysisOrchestrator
from app.tools.datetime_tool import DateTimeTool
from input.models import AnalysisRequest


class DateTimeToolTests(unittest.TestCase):
    def test_supported_date_and_time_questions_are_recognized(self):
        tool = DateTimeTool()
        with tempfile.TemporaryDirectory() as directory:
            for prompt in (
                "What is today's date?",
                "What is the current date?",
                "What day is today?",
                "What time is it?",
                "Tell me today's date.",
            ):
                with self.subTest(prompt=prompt):
                    request = AnalysisRequest(directory, prompt)
                    self.assertTrue(tool.is_applicable(request))

    def test_unrelated_defect_is_not_classified_as_datetime(self):
        request = AnalysisRequest(".", "SensorStatus becomes UNAVAILABLE")
        self.assertFalse(DateTimeTool().is_applicable(request))

    def test_orchestrator_answers_locally_without_other_tools_or_agent(self):
        agent = Mock()
        repository_tool = Mock(phase=100)
        rag_tool = Mock(phase=110)
        datetime_tool = DateTimeTool()
        with tempfile.TemporaryDirectory() as directory:
            request = AnalysisRequest(
                directory,
                "What is today's date?",
                blf_path=str(Path(directory) / "optional.blf"),
            )
            with patch(
                "app.orchestrator.orchestrator.get_applicable_tools",
                return_value=[datetime_tool, repository_tool, rag_tool],
            ):
                result = AnalysisOrchestrator(agent=agent).run(request)

        actual = datetime.now().astimezone().date().isoformat()
        self.assertEqual(result.evidence[0].details["date"], actual)
        self.assertEqual(result.confidence, "high")
        self.assertIn("local system clock", result.recommendation)
        agent.analyze.assert_not_called()
        repository_tool.run.assert_not_called()
        rag_tool.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()