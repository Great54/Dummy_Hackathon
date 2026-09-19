"""Analysis Orchestrator: the single entry point invoked when the user
clicks START ANALYSIS.

Flow (Phase 1):
    AnalysisRequest -> select applicable tools -> run tools -> Evidence
                     -> ReasoningAgent.analyze() -> AnalysisResult

No fixed tool order is hard-coded here; tools are selected purely by
`is_applicable`, so future tools plug in without changing this file. A
full agentic tool-selection loop (agent decides next tool based on
evidence so far) is intentionally out of scope for Phase 1.
"""

import logging
import threading
from typing import Callable, Optional

from app.agent.reasoning_agent import ReasoningAgent
from app.orchestrator.cancellation import AnalysisCancelledError
from app.orchestrator.evidence import AnalysisResult, Evidence
from app.tools.registry import get_applicable_tools
from input.models import AnalysisRequest

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str], None]


class AnalysisOrchestrator:
    """Coordinates tools and the reasoning agent for a single analysis run."""

    def __init__(self, agent: Optional[ReasoningAgent] = None) -> None:
        self._agent = agent or ReasoningAgent()
        self._cancel_event = threading.Event()
        self._current_tool = None

    def cancel(self) -> None:
        self._cancel_event.set()
        current_tool = self._current_tool
        if current_tool is not None and hasattr(current_tool, "cancel"):
            current_tool.cancel()

    def run(
        self,
        request: AnalysisRequest,
        on_progress: Optional[ProgressCallback] = None,
    ) -> AnalysisResult:
        self._cancel_event.clear()

        def report(message: str) -> None:
            logger.info(message)
            if on_progress:
                on_progress(message)

        report("Selecting applicable analysis tools...")
        applicable_tools = sorted(
            get_applicable_tools(request), key=lambda tool: tool.phase
        )

        evidence: list[Evidence] = []
        if not applicable_tools:
            report(
                "No analysis tools apply to this request - proceeding with "
                "defect description and repository context only."
            )
        for tool in applicable_tools:
            if self._cancel_event.is_set():
                raise AnalysisCancelledError("Analysis cancelled by the user.")
            tool_label = tool.name.removesuffix(" Analysis")
            report(f"Analyzing {tool_label}...")
            self._current_tool = tool
            try:
                evidence.append(
                    tool.run(
                        request,
                        on_progress=report,
                        prior_evidence=list(evidence),
                    )
                )
            except AnalysisCancelledError:
                raise
            except Exception as error:  # noqa: BLE001 - captured as evidence
                logger.exception("Tool %s failed", tool.name)
                report(f"{tool.name} failed: {error}")
                evidence.append(
                    Evidence(
                        source=tool.name,
                        summary=f"Tool failed to run: {error}",
                        details={},
                        severity="error",
                    )
                )
            finally:
                self._current_tool = None

        if self._cancel_event.is_set():
            raise AnalysisCancelledError("Analysis cancelled by the user.")
        report("Correlating evidence and generating root cause with Gemini...")
        result = self._agent.analyze(request, evidence)

        report("Analysis complete.")
        return result
