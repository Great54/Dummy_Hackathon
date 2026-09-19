"""Select the configured reasoning provider without changing orchestration."""

from __future__ import annotations

import os
from typing import Protocol

from dotenv import load_dotenv

from app.agent.gemini_client import get_gemini_client
from app.agent.ollama_client import OllamaClient


class ReasoningClient(Protocol):
    @property
    def model(self) -> str: ...

    def generate_json(self, prompt: str) -> str: ...


def get_reasoning_client() -> ReasoningClient:
    """Return Gemini by default; use local Ollama only when explicitly selected."""

    load_dotenv()
    provider = os.getenv("LLM_PROVIDER", "").strip().lower() or "gemini"
    if provider == "gemini":
        return get_gemini_client()
    if provider == "ollama":
        return OllamaClient()
    raise ValueError("LLM_PROVIDER must be either 'gemini' or 'ollama'.")
