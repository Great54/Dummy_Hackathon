"""Deterministic answers for standalone local date and time questions."""

from datetime import datetime
import re
from typing import Callable, Optional

from app.orchestrator.evidence import Evidence
from app.tools.base import AnalysisTool
from input.models import AnalysisRequest

_QUESTION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(?:what is|what's) (?:the )?(?:today's date|current date)",
        r"what day is today",
        r"what time is it",
        r"(?:what is|what's) (?:the )?current time",
        r"tell me today's date",
    )
)


class DateTimeTool(AnalysisTool):
    """Return the local system clock without repository or model access."""

    name = "Date/Time Tool"
    phase = -100

    def is_applicable(self, request: AnalysisRequest) -> bool:
        question = request.defect_description.strip().rstrip("?.! ")
        return any(pattern.fullmatch(question) for pattern in _QUESTION_PATTERNS)

    def run(
        self,
        request: AnalysisRequest,
        on_progress: Optional[Callable[[str], None]] = None,
        prior_evidence: Optional[list[Evidence]] = None,
    ) -> Evidence:
        timestamp = datetime.now().astimezone()
        local_iso = timestamp.isoformat(timespec="seconds")
        if on_progress:
            on_progress("Read the local system date and time.")
        return Evidence(
            source=self.name,
            summary=f"Local system date and time: {local_iso}",
            details={
                "date": timestamp.date().isoformat(),
                "time": timestamp.timetz().isoformat(timespec="seconds"),
                "local_datetime": local_iso,
                "evidence_found": True,
            },
        )