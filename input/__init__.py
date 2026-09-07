from dataclasses import dataclass


@dataclass
class AnalysisRequest:
    repo_path: str
    defect_description: str
    blf_path: str