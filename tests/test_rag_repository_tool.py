import tempfile
import unittest
from pathlib import Path

import numpy as np
from unittest.mock import patch

from app.orchestrator.cancellation import AnalysisCancelledError
from app.orchestrator.evidence import AnalysisResult, Evidence
from app.orchestrator.orchestrator import AnalysisOrchestrator
from app.rag.index import RepositoryVectorIndex
from app.tools.rag_repository_tool import RagRepositoryTool
from app.tools.repository_tool import RepositoryTool
from input.models import AnalysisRequest


class FakeEmbeddings:
    model_name = "test-embeddings"

    def encode(self, texts):
        return np.asarray(
            [[float("0x1234" in text.lower()), float("response" in text.lower()), 1.0] for text in texts],
            dtype="float32",
        )


class FailingIndex:
    def ensure(self, *args, **kwargs):
        raise RuntimeError("embedding unavailable")


class CapturingAgent:
    def __init__(self):
        self.evidence = []

    def analyze(self, request, evidence):
        self.evidence = evidence
        return AnalysisResult("Undetermined", "Investigate", evidence)


class FakeLogTool:
    name = "Fake TTL Analysis"
    phase = 0

    def is_applicable(self, request):
        return True

    def run(self, request, on_progress=None, prior_evidence=None):
        return Evidence(
            self.name,
            "SOME/IP request observed without response",
            {"service_id": "0x1234", "method_id": "0x0002"},
        )


class RagRepositoryToolTests(unittest.TestCase):
    def setUp(self):
        self.repository_temp = tempfile.TemporaryDirectory()
        self.cache_temp = tempfile.TemporaryDirectory()
        self.repository = Path(self.repository_temp.name).resolve()
        self.cache = Path(self.cache_temp.name).resolve()

    def tearDown(self):
        self.repository_temp.cleanup()
        self.cache_temp.cleanup()

    def write(self, relative_path, content):
        path = self.repository / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def tool(self):
        return RagRepositoryTool(
            RepositoryVectorIndex(cache_root=self.cache, embeddings=FakeEmbeddings())
        )

    def test_repository_only_analysis_returns_bounded_rag_evidence(self):
        self.write("src/service.cpp", "void handleResponseTimeout();\n")
        evidence = self.tool().run(
            AnalysisRequest(str(self.repository), "response timeout")
        )
        self.assertTrue(evidence.details["evidence_found"])
        self.assertEqual(evidence.details["chunks"][0]["path"], "src/service.cpp")
        self.assertNotIn("chunk_id", evidence.details["chunks"][0])

    def test_log_identifier_influences_retrieval(self):
        self.write("config/someip.json", '{"service_id":"0x1234"}\n')
        prior = [Evidence("TTL Analysis", "request observed", {"service_id": "0x1234"})]
        evidence = self.tool().run(
            AnalysisRequest(str(self.repository), "response missing"),
            prior_evidence=prior,
        )
        self.assertIn("0x1234", evidence.details["retrieval_query"])
        self.assertEqual(evidence.details["chunks"][0]["path"], "config/someip.json")

    def test_rag_failure_returns_fallback_evidence_and_progress(self):
        messages = []
        evidence = RagRepositoryTool(FailingIndex()).run(
            AnalysisRequest(str(self.repository), "response missing"),
            on_progress=messages.append,
        )
        self.assertEqual(evidence.severity, "warning")
        self.assertTrue(evidence.details["unavailable"])
        self.assertTrue(any("continuing with deterministic" in message for message in messages))

    def test_missing_repository_is_not_applicable(self):
        request = AnalysisRequest(str(self.repository / "missing"), "failure")
        self.assertFalse(self.tool().is_applicable(request))

    def test_cancel_is_propagated(self):
        tool = self.tool()
        tool.cancel()
        with self.assertRaises(AnalysisCancelledError):
            tool._check_cancelled()

    def test_orchestrator_orders_log_keyword_rag_then_reasoning(self):
        self.write("config/someip.json", '{"service_id":"0x1234","method_id":"0x0002"}\n')
        agent = CapturingAgent()
        tools = [self.tool(), RepositoryTool(), FakeLogTool()]
        with patch(
            "app.orchestrator.orchestrator.get_applicable_tools",
            return_value=tools,
        ):
            AnalysisOrchestrator(agent).run(
                AnalysisRequest(str(self.repository), "SOME/IP response missing")
            )

        self.assertEqual(
            [item.source for item in agent.evidence],
            [
                "Fake TTL Analysis",
                "Repository Analysis",
                "Repository RAG",
                "Runtime Log Availability",
            ],
        )
        rag = next(item for item in agent.evidence if item.source == "Repository RAG")
        self.assertIn("0x1234", rag.details["retrieval_query"])
        self.assertGreater(rag.details["keyword_matches_used"], 0)

    def test_orchestrator_continues_when_rag_fails(self):
        self.write("src/service.cpp", "response timeout handling\n")
        agent = CapturingAgent()
        tools = [RepositoryTool(), RagRepositoryTool(FailingIndex())]
        with patch(
            "app.orchestrator.orchestrator.get_applicable_tools",
            return_value=tools,
        ):
            result = AnalysisOrchestrator(agent).run(
                AnalysisRequest(str(self.repository), "response timeout")
            )
        self.assertEqual(result.evidence[0].source, "Repository Analysis")
        self.assertEqual(result.evidence[1].severity, "warning")


if __name__ == "__main__":
    unittest.main()