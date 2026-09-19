import json
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from app.agent.ollama_client import (
    DEFAULT_OLLAMA_MODEL,
    OllamaClient,
    OllamaConfigurationError,
)
from app.agent.provider import get_reasoning_client


class FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class LlmProviderTests(unittest.TestCase):
    def test_gemini_is_default_provider(self):
        with patch.dict(os.environ, {"LLM_PROVIDER": ""}, clear=False):
            client = get_reasoning_client()
        self.assertEqual(client.__class__.__name__, "GeminiClient")

    def test_ollama_is_explicit_provider(self):
        with patch.dict(os.environ, {"LLM_PROVIDER": "ollama"}, clear=False):
            client = get_reasoning_client()
        self.assertIsInstance(client, OllamaClient)

    def test_invalid_provider_is_rejected(self):
        with patch.dict(os.environ, {"LLM_PROVIDER": "unsupported"}, clear=False):
            with self.assertRaisesRegex(ValueError, "LLM_PROVIDER"):
                get_reasoning_client()

    def test_ollama_uses_schema_and_returns_response(self):
        client = OllamaClient()
        calls = []

        def fake_urlopen(request, timeout):
            calls.append((request, timeout))
            return FakeResponse({"response": '{"root_cause":"ok"}'})

        with patch.dict(os.environ, {"OLLAMA_MODEL": "test-model"}, clear=False), patch(
            "app.agent.ollama_client.urlopen", side_effect=fake_urlopen
        ):
            response = client.generate_json("prompt")

        body = json.loads(calls[0][0].data.decode("utf-8"))
        self.assertEqual(body["model"], "test-model")
        self.assertFalse(body["stream"])
        self.assertIn("root_cause", body["format"]["properties"])
        self.assertIn("ok", response)

    def test_missing_ollama_service_has_install_guidance(self):
        client = OllamaClient()
        with patch(
            "app.agent.ollama_client.urlopen",
            side_effect=URLError("connection refused"),
        ):
            with self.assertRaisesRegex(OllamaConfigurationError, "Ollama is not running"):
                client.generate_json("prompt")

    def test_missing_ollama_model_has_pull_guidance(self):
        client = OllamaClient()
        http_error = HTTPError("http://localhost", 404, "not found", {}, None)
        with patch(
            "app.agent.ollama_client.urlopen",
            side_effect=http_error,
        ), patch.dict(os.environ, {"OLLAMA_MODEL": "missing-model"}, clear=False):
            with self.assertRaisesRegex(OllamaConfigurationError, "ollama pull missing-model"):
                client.generate_json("prompt")

    def test_default_ollama_model_is_coder_model(self):
        self.assertEqual(DEFAULT_OLLAMA_MODEL, "qwen2.5-coder:14b")


if __name__ == "__main__":
    unittest.main()
