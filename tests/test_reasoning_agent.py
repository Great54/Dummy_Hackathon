import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.agent.gemini_client import (
    ANALYSIS_RESPONSE_SCHEMA,
    DEFAULT_MODEL,
    GeminiAnalysisError,
    GeminiClient,
    GeminiConfigurationError,
)
from app.agent.reasoning_agent import INSUFFICIENT_EVIDENCE, ReasoningAgent
from app.orchestrator.evidence import Evidence
from app.orchestrator.orchestrator import AnalysisOrchestrator
from input.models import AnalysisRequest


STRUCTURED_RESPONSE = {
    "root_cause": "The supplied TTL evidence suggests a service definition mismatch.",
    "recommendation": "Compare the configured service and method identifiers.",
    "correlation": "Compare the observed log with the supplied repository evidence.",
    "confidence": "medium",
    "hypotheses": ["The consumer may use a different interface version."],
    "next_investigation_steps": ["Capture SOME/IP request and response traffic."],
}


class FakeGeminiClient:
    def __init__(self, response=None):
        selected = response if response is not None else STRUCTURED_RESPONSE
        self.response = selected if isinstance(selected, str) else json.dumps(selected)
        self.prompts = []

    def generate_json(self, prompt):
        self.prompts.append(prompt)
        return self.response


@patch.dict(os.environ, {"RAG_ENABLED": "false"})
class ReasoningAgentTests(unittest.TestCase):
    def test_structured_response_creates_analysis_result(self) -> None:
        client = FakeGeminiClient()
        agent = ReasoningAgent(client)
        evidence = [Evidence("TTL Analysis", "Found service definition", {"line": 4})]

        result = agent.analyze(AnalysisRequest("C:/repo", "Response missing"), evidence)

        self.assertEqual(result.confidence, "medium")
        self.assertEqual(result.recommendation, STRUCTURED_RESPONSE["recommendation"])
        self.assertEqual(result.hypotheses, STRUCTURED_RESPONSE["hypotheses"])
        self.assertEqual(result.evidence, evidence)
        self.assertEqual(result.raw_ai_response, client.response)

    def test_fenced_json_is_parsed_without_string_splitting(self) -> None:
        response = "```json\n" + json.dumps(STRUCTURED_RESPONSE) + "\n```"
        result = ReasoningAgent(FakeGeminiClient(response=response)).analyze(
            AnalysisRequest("C:/repo", "Response missing"),
            [Evidence("TTL Analysis", "Relevant definition", {})],
        )
        self.assertEqual(result.confidence, "medium")
        self.assertEqual(result.root_cause, STRUCTURED_RESPONSE["root_cause"])

    def test_empty_evidence_uses_exact_insufficient_statement(self) -> None:
        client = FakeGeminiClient()
        result = ReasoningAgent(client).analyze(
            AnalysisRequest("C:/repo", "Response missing"), []
        )
        self.assertEqual(result.root_cause, INSUFFICIENT_EVIDENCE)
        self.assertEqual(result.confidence, "medium")
        self.assertIn("No log evidence was collected", client.prompts[0])
        self.assertIn("Provided optional input files (names only): {}", client.prompts[0])

    def test_input_names_and_bounded_evidence_reach_gemini(self) -> None:
        client = FakeGeminiClient()
        request = AnalysisRequest(
            "C:/repo",
            "SOME/IP response missing",
            ttl_path="C:/captures/vehicle.ttl",
        )
        ReasoningAgent(client).analyze(
            request,
            [Evidence("TTL Analysis", "Found service", {"service": "Example"})],
        )
        prompt = client.prompts[0]
        self.assertIn('"TTL": "vehicle.ttl"', prompt)
        self.assertIn('"source":"TTL Analysis"', prompt)
        self.assertNotIn("C:/captures/vehicle.ttl", prompt)

    def test_large_evidence_keeps_all_sources_in_valid_json(self) -> None:
        client = FakeGeminiClient()
        evidence = [
            Evidence("TTL Analysis", "TTL summary", {"data": "x" * 70_000}),
            Evidence("Repository Analysis", "Repository summary", {"matches": ["result"]}),
        ]
        ReasoningAgent(client).analyze(
            AnalysisRequest("C:/repo", "SOME/IP response missing"), evidence
        )
        prompt = client.prompts[0]
        evidence_text = prompt.split("Bounded structured evidence:\n", 1)[1].split(
            "\n\nAUTOSAR REQUIREMENT EVIDENCE", 1
        )[0]
        parsed = json.loads(evidence_text)
        self.assertEqual(
            [item["source"] for item in parsed],
            ["TTL Analysis", "Repository Analysis"],
        )
        self.assertTrue(parsed[0]["details"]["details_truncated"])

    def test_prompt_distinguishes_static_rag_from_runtime_evidence(self) -> None:
        client = FakeGeminiClient()
        evidence = [
            Evidence("TTL Analysis", "Request observed", {"service_id": "0x1234"}),
            Evidence(
                "Repository RAG",
                "Retrieved static source",
                {"chunks": [{"path": "src/service.cpp", "text": "handleResponse();"}]},
            ),
        ]
        ReasoningAgent(client).analyze(
            AnalysisRequest("C:/repo", "Response missing"), evidence
        )
        prompt = client.prompts[0]
        self.assertIn("Static repository evidence does not prove", prompt)
        self.assertIn("runtime observations", prompt)
        self.assertIn("Repository RAG", prompt)

    def test_no_log_orchestrator_path_reaches_reasoning_agent(self) -> None:
        client = FakeGeminiClient()
        result = AnalysisOrchestrator(ReasoningAgent(client)).run(
            AnalysisRequest("C:/repo", "Intermittent communication failure")
        )
        self.assertEqual(result.root_cause, INSUFFICIENT_EVIDENCE)
        availability = next(
            item for item in result.evidence
            if item.source == "Runtime Log Availability"
        )
        self.assertFalse(availability.details["runtime_log_evidence_available"])
        self.assertIn("Runtime log evidence is unavailable", client.prompts[0])
        self.assertTrue(
            any(
                item.source == "AUTOSAR Official Specification"
                and item.details["status"] == "unavailable"
                for item in result.evidence
            )
        )
        self.assertEqual(len(client.prompts), 1)

    def test_reasoning_failure_preserves_tool_evidence_without_error_secrets(self) -> None:
        class FailingAgent:
            def analyze(self, request, evidence):
                raise RuntimeError("GEMINI_API_KEY=do-not-show")

        with tempfile.TemporaryDirectory() as repository:
            source = Path(repository) / "diagnostic.c"
            source.write_text(
                "SensorStatus = UNAVAILABLE;\n", encoding="utf-8"
            )
            result = AnalysisOrchestrator(FailingAgent()).run(
                AnalysisRequest(repository, "SensorStatus becomes UNAVAILABLE")
            )

        sources = [item.source for item in result.evidence]
        self.assertIn("Repository Analysis", sources)
        self.assertIn("Runtime Log Availability", sources)
        self.assertIn("Reasoning Agent", sources)
        self.assertEqual(result.root_cause, INSUFFICIENT_EVIDENCE)
        self.assertNotIn("do-not-show", repr(result.to_dict()))

    def test_ttl_evidence_flows_through_orchestrator_and_reasoning_agent(self) -> None:
        client = FakeGeminiClient()
        with tempfile.TemporaryDirectory() as directory:
            ttl_path = Path(directory) / "vehicle.ttl"
            ttl_path.write_text(
                "@prefix ex: <http://example.test/> .\n"
                'ex:VehicleService a ex:SomeIpService ; ex:methodId "0x1001" .\n',
                encoding="utf-8",
            )
            result = AnalysisOrchestrator(ReasoningAgent(client)).run(
                AnalysisRequest(
                    directory,
                    "SOME/IP response is not received",
                    ttl_path=str(ttl_path),
                )
            )

        self.assertIn("TTL Analysis", [item.source for item in result.evidence])
        self.assertIn("Repository Analysis", [item.source for item in result.evidence])
        self.assertIn("TTL Analysis", client.prompts[0])
        self.assertEqual(result.confidence, "medium")


class GeminiClientTests(unittest.TestCase):
    def test_default_model_is_current_supported_model(self) -> None:
        self.assertEqual(DEFAULT_MODEL, "gemini-3.6-flash")

    def test_missing_key_raises_clear_runtime_error(self) -> None:
        client = GeminiClient()
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}, clear=False):
            with self.assertRaisesRegex(GeminiConfigurationError, "GEMINI_API_KEY"):
                client.generate_json("test")

    def test_json_schema_is_sent_to_sdk(self) -> None:
        calls = []

        class Models:
            def generate_content(self, **kwargs):
                calls.append(kwargs)
                return type("Response", (), {"text": json.dumps(STRUCTURED_RESPONSE)})()

        client = GeminiClient()
        client._client = type("Client", (), {"models": Models()})()
        client.generate_json("prompt")

        self.assertEqual(
            calls[0]["config"]["response_schema"], ANALYSIS_RESPONSE_SCHEMA
        )
        self.assertEqual(calls[0]["config"]["response_mime_type"], "application/json")

    def test_sdk_failure_is_wrapped_without_sensitive_details(self) -> None:
        class Models:
            def generate_content(self, **kwargs):
                raise RuntimeError("secret request details")

        client = GeminiClient()
        client._client = type("Client", (), {"models": Models()})()
        with self.assertRaises(GeminiAnalysisError) as context:
            client.generate_json("prompt")
        self.assertNotIn("secret request details", str(context.exception))


if __name__ == "__main__":
    unittest.main()
