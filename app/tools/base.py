"""Interface every analysis tool (BLF, MF4, PCAPNG, TTL, repository search,
source code inspection, SOME/IP config, ...) must implement.

Tools are deterministic, structured-evidence producers. They must never load
entire large files into memory and never call Gemini themselves.
"""

from abc import ABC, abstractmethod
from typing import Callable, Optional

from app.orchestrator.evidence import Evidence
from input.models import AnalysisRequest


class AnalysisTool(ABC):
    """Base class for a pluggable analysis tool."""

    name: str = "UnnamedTool"
    phase: int = 0

    @abstractmethod
    def is_applicable(self, request: AnalysisRequest) -> bool:
        """Return True if this tool has the input it needs to run."""

    @abstractmethod
    def run(
        self,
        request: AnalysisRequest,
        on_progress: Optional[Callable[[str], None]] = None,
        prior_evidence: Optional[list[Evidence]] = None,
    ) -> Evidence:
        """Execute the tool and return a single structured Evidence item."""
