"""Lazy, minimal wrapper around the google-genai SDK.

The client is NOT created at import time - a missing GEMINI_API_KEY only
raises when Gemini is actually requested, so the rest of the application
(GUI, orchestrator, tools) can run without a configured key.
"""

import os
import logging
from typing import Optional

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-3.6-flash"

ANALYSIS_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "root_cause": {"type": "string"},
        "recommendation": {"type": "string"},
        "confidence": {
            "type": "string",
            "enum": ["low", "medium", "high"],
        },
        "hypotheses": {
            "type": "array",
            "items": {"type": "string"},
        },
        "next_investigation_steps": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": [
        "root_cause",
        "recommendation",
        "confidence",
        "hypotheses",
        "next_investigation_steps",
    ],
}


class GeminiConfigurationError(RuntimeError):
    """Gemini cannot run because required configuration is missing."""


class GeminiAnalysisError(RuntimeError):
    """Gemini failed while generating an analysis."""


class GeminiClient:
    """Thin, lazily-initialized wrapper around genai.Client."""

    def __init__(self) -> None:
        self._client = None

    @property
    def model(self) -> str:
        return os.getenv("GEMINI_MODEL", DEFAULT_MODEL)

    def _ensure_client(self):
        if self._client is not None:
            return self._client

        load_dotenv()
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise GeminiConfigurationError(
                "GEMINI_API_KEY is not set. Please configure it in your .env file."
            )

        from google import genai  # imported lazily so tests can run without it

        self._client = genai.Client(api_key=api_key)
        return self._client

    def generate_json(self, prompt: str) -> str:
        """Send a prompt to Gemini requesting a JSON response and return the raw text."""

        client = self._ensure_client()
        try:
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "response_schema": ANALYSIS_RESPONSE_SCHEMA,
                },
            )
        except Exception as error:
            status = getattr(error, "status", None)
            code = getattr(error, "code", None)
            message = _safe_error_message(error)
            logger.error(
                "Gemini request failed: exception=%s status=%s code=%s "
                "model=%s request_reached_gemini=true message=%s",
                type(error).__name__,
                status,
                code,
                self.model,
                message,
            )
            raise GeminiAnalysisError(
                "Gemini could not complete the analysis. Check the configured "
                f"model ({self.model}), network connection, and API access."
            ) from error

        if not response.text:
            raise GeminiAnalysisError("Gemini returned an empty analysis response.")
        return response.text


_default_client: Optional[GeminiClient] = None


def get_gemini_client() -> GeminiClient:
    """Return a shared, lazily-initialized GeminiClient instance."""

    global _default_client
    if _default_client is None:
        _default_client = GeminiClient()
    return _default_client


def _safe_error_message(error: Exception) -> str:
    message = " ".join(str(error).split())[:1000]
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        message = message.replace(api_key, "<redacted>")
    return message
