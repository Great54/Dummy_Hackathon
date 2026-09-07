from dataclasses import dataclass
from typing import Optional


@dataclass
class AnalysisRequest:
    repo_path: str
    defect_description: str

    blf_path: Optional[str] = None
    mf4_path: Optional[str] = None
    pcapng_path: Optional[str] = None
    ttl_path: Optional[str] = None