"""Optional local Ollama client for private, token-free reasoning.

Ollama is intentionally not a Python dependency. It exposes a local HTTP API,
so this client uses only Python's standard library and never sends evidence to
an external service.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv

from app.agent.gemini_client import ANALYSIS_RESPONSE_SCHEMA

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:14b"


class OllamaConfigurationError(RuntimeError):
    """Ollama is unavailable or its configured model is not installed."""


class OllamaAnalysisError(RuntimeError):
    """The local Ollama server could not complete the request."""


class OllamaClient:
    """Minimal client for Ollama's local /api/generate endpoint."""

    @property
    def model(self) -> str:
        return os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL).strip()

    @property
    def host(self) -> str:
        return os.getenv("OLLAMA_HOST", DEFAULT_OLLAMA_HOST).rstrip("/")

    def generate_json(self, prompt: str) -> str:
        load_dotenv()
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": ANALYSIS_RESPONSE_SCHEMA,
            "options": {"temperature": 0.2},
        }
        request = Request(
            f"{self.host}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=300) as response:
                body: dict[str, Any] = json.loads(response.read().decode("utf-8"))
        except URLError as error:
            raise OllamaConfigurationError(
                "Ollama is not running. Install Ollama, start its local service, "
                f"then pull the configured model: ollama pull {self.model}"
            ) from error
        except HTTPError as error:
            message = _safe_http_error(error)
            if error.code == 404:
                raise OllamaConfigurationError(
                    f"Ollama model '{self.model}' is not available. Run: "
                    f"ollama pull {self.model}"
                ) from error
            logger.error(
                "Ollama request failed: status=%s model=%s message=%s",
                error.code,
                self.model,
                message,
            )
            raise OllamaAnalysisError(
                f"Ollama could not complete the analysis (HTTP {error.code})."
            ) from error
        except (TimeoutError, json.JSONDecodeError) as error:
            raise OllamaAnalysisError("Ollama returned an invalid or timed-out response.") from error

        answer = body.get("response")
        if not isinstance(answer, str) or not answer.strip():
            raise OllamaAnalysisError("Ollama returned an empty analysis response.")
        return answer


def _safe_http_error(error: HTTPError) -> str:
    try:
        return " ".join(error.read(2_000).decode("utf-8", errors="replace").split())
    except OSError:
        return ""
