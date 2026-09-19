"""Reasoning agent: correlates bounded Evidence with the defect description
and asks Gemini to produce a structured root-cause analysis.

Gemini performs reasoning/correlation only - it never receives raw log
files or full repository contents, only compact Evidence summaries.
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional

from app.agent.provider import ReasoningClient, get_reasoning_client
from app.orchestrator.evidence import AnalysisResult, Evidence
from input.models import AnalysisRequest

logger = logging.getLogger(__name__)

INSUFFICIENT_EVIDENCE = "Insufficient evidence to determine the root cause."
MAX_EVIDENCE_PROMPT_CHARACTERS = 60_000
VALID_CONFIDENCE = {"low", "medium", "high"}

RESPONSE_FORMAT_HINT = """
Respond with ONLY a single JSON object, no surrounding text, using exactly this shape:
{
  "root_cause": "<confirmed root cause if the evidence supports it, otherwise the most \
likely explanation clearly labeled as unconfirmed>",
  "recommendation": "<concrete recommended action>",
  "confidence": "low" | "medium" | "high",
  "hypotheses": ["<additional plausible explanations that are NOT confirmed>"],
  "next_investigation_steps": ["<specific next steps, e.g. which log/config to capture>"]
}

Rules:
- CONFIRMED EVIDENCE is only the supplied deterministic tool evidence.
- Repository evidence is observational: claim a repository fact only when a returned
    match supports it. Never invent file paths, line numbers, identifiers, constants,
    functions, configuration values, or source-code behavior.
- A repository search result shows text at a location; it does not prove runtime
    execution or causality.
- "root_cause" is the LIKELY ROOT CAUSE, not a confirmed fact, unless the evidence
    directly proves it. State uncertainty explicitly.
- Put alternative unconfirmed explanations only in "hypotheses".
- Never invent identifiers, addresses, ports, timestamps, source locations, or values.
- If evidence is empty or insufficient, set "root_cause" exactly to:
    "Insufficient evidence to determine the root cause."
- Use "recommendation" for a practical action and "next_investigation_steps" for
    specific missing evidence to collect.
"""


class ReasoningAgent:
    """Turns AnalysisRequest + Evidence into a structured AnalysisResult."""

    def __init__(self, client: Optional[ReasoningClient] = None) -> None:
        self._client = client or get_reasoning_client()

    def analyze(
        self, request: AnalysisRequest, evidence: list[Evidence]
    ) -> AnalysisResult:
        prompt = self._build_prompt(request, evidence)
        raw_text = self._client.generate_json(prompt)
        parsed = self._parse_response(raw_text)

        substantive_evidence = any(
            item.severity != "error"
            and item.details.get("evidence_found", True)
            for item in evidence
        )
        root_cause = _text(parsed.get("root_cause"))
        if not substantive_evidence:
            root_cause = INSUFFICIENT_EVIDENCE

        return AnalysisResult(
            root_cause=root_cause or INSUFFICIENT_EVIDENCE,
            recommendation=_text(parsed.get("recommendation")),
            evidence=evidence,
            raw_ai_response=raw_text,
            confidence=_confidence(parsed.get("confidence")),
            hypotheses=_string_list(parsed.get("hypotheses")),
            next_investigation_steps=_string_list(
                parsed.get("next_investigation_steps")
            ),
        )

    def _build_prompt(
        self, request: AnalysisRequest, evidence: list[Evidence]
    ) -> str:
        if evidence:
            evidence_block = _bounded_evidence_json(evidence)
        else:
            evidence_block = (
                "No log evidence was collected for this analysis. Only the "
                "defect description and repository path are available."
            )

        supplied_inputs = {
            name: file_name
            for name, file_name in {
                "BLF": _file_name(request.blf_path),
                "MF4": _file_name(request.mf4_path),
                "PCAPNG": _file_name(request.pcapng_path),
                "TTL": _file_name(request.ttl_path),
            }.items()
            if file_name is not None
        }

        return (
            "You are an automotive software and communication defect analysis "
            "assistant. Analyze the defect using ONLY the information given "
            "below. Do not invent facts that are not supported by the evidence.\n\n"
            f"Repository path: {request.repo_path}\n"
            f"Defect description: {request.defect_description}\n\n"
            "Provided optional input files (names only): "
            f"{json.dumps(supplied_inputs, sort_keys=True)}\n\n"
            "Bounded structured evidence:\n"
            f"{evidence_block}\n\n"
            f"{RESPONSE_FORMAT_HINT}"
        )

    def _parse_response(self, raw_text: str) -> dict[str, Any]:
        candidate = raw_text.strip()
        if candidate.startswith("```"):
            lines = candidate.splitlines()[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            candidate = "\n".join(lines).strip()

        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            parsed = _extract_json_object(candidate)

        if not isinstance(parsed, dict):
            logger.warning("Gemini response did not contain a JSON object.")
            return {
                "root_cause": INSUFFICIENT_EVIDENCE,
                "recommendation": "Review the available evidence and retry the AI analysis.",
                "confidence": "low",
                "hypotheses": [],
                "next_investigation_steps": [
                    "Verify the Gemini model supports structured JSON output."
                ],
            }
        return parsed


def _extract_json_object(text: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _confidence(value: Any) -> str:
    normalized = _text(value).lower()
    return normalized if normalized in VALID_CONFIDENCE else "low"


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _file_name(path_text: str | None) -> str | None:
    return Path(path_text).name if path_text else None


def _bounded_evidence_json(evidence: list[Evidence]) -> str:
    per_item_budget = max(
        2_000,
        (MAX_EVIDENCE_PROMPT_CHARACTERS - 2_000) // max(len(evidence), 1),
    )
    bounded_items: list[dict[str, Any]] = []
    for item in evidence:
        details_json = json.dumps(
            item.details,
            default=str,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        details: Any = item.details
        if len(details_json) > per_item_budget:
            details = {
                "bounded_details_excerpt": details_json[:per_item_budget],
                "details_truncated": True,
            }
        bounded_items.append(
            {
                "source": item.source,
                "summary": item.summary,
                "severity": item.severity,
                "details": details,
            }
        )
    return json.dumps(
        bounded_items,
        default=str,
        ensure_ascii=True,
        separators=(",", ":"),
    )
