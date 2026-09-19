"""Structured evidence and analysis result models shared by tools, the
reasoning agent and the GUI. Kept dependency-free and JSON-serializable."""

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class Evidence:
    """A single, bounded finding produced by an analysis tool."""

    source: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    severity: str = "info"  # "info" | "warning" | "error"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    """Final, structured output of an analysis run."""

    root_cause: str
    recommendation: str
    evidence: list[Evidence]
    raw_ai_response: Optional[str] = None
    confidence: str = "low"  # "low" | "medium" | "high"
    hypotheses: list[str] = field(default_factory=list)
    next_investigation_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
