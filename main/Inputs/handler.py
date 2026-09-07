from pathlib import Path

from .models import AnalysisRequest


def create_analysis_request(
    repo_path: str,
    defect_description: str,
    blf_path: str
) -> AnalysisRequest:

    # Check repository path
    repo = Path(repo_path)

    if not repo.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")

    if not repo.is_dir():
        raise ValueError(f"Repository path is not a directory: {repo_path}")

    # Check defect description
    if not defect_description.strip():
        raise ValueError("Defect description cannot be empty.")

    # Check BLF path
    blf = Path(blf_path)

    if not blf.exists():
        raise ValueError(f"BLF file does not exist: {blf_path}")

    if not blf.is_file():
        raise ValueError(f"BLF path is not a file: {blf_path}")

    # Create the analysis request
    return AnalysisRequest(
        repo_path=str(repo.resolve()),
        defect_description=defect_description.strip(),
        blf_path=str(blf.resolve())
    )