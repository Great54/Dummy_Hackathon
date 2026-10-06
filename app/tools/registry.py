"""Central registry of available analysis tools."""

from app.tools.base import AnalysisTool
from app.tools.autosar_requirement_tool import AUTOSARRequirementTool
from app.tools.blf_tool import BlfTool
from app.tools.datetime_tool import DateTimeTool
from app.tools.rag_repository_tool import RagRepositoryTool
from app.tools.repository_tool import RepositoryTool
from app.tools.ttl_trace_tool import TtlTraceTool
from app.tools.ttl_tool import TtlTool
from input.models import AnalysisRequest

_REGISTERED_TOOLS: list[AnalysisTool] = [
    DateTimeTool(),
    BlfTool(),
    TtlTraceTool(),
    TtlTool(),
    RepositoryTool(),
    RagRepositoryTool(),
    AUTOSARRequirementTool(),
]


def register_tool(tool: AnalysisTool) -> None:
    _REGISTERED_TOOLS.append(tool)


def get_registered_tools() -> list[AnalysisTool]:
    return list(_REGISTERED_TOOLS)


def get_applicable_tools(request: AnalysisRequest) -> list[AnalysisTool]:
    return [tool for tool in _REGISTERED_TOOLS if tool.is_applicable(request)]
