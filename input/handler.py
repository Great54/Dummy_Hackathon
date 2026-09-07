from pathlib import Path

from .models import AnalysisRequest


def validate_file(file_path: str, file_type: str) -> str:
    path = Path(file_path)

    if not path.exists():
        raise ValueError(
            f"{file_type} file does not exist: {file_path}"
        )

    if not path.is_file():
        raise ValueError(
            f"{file_type} path is not a file: {file_path}"
        )

    return str(path.resolve())


def create_analysis_request(
    repo_path: str,
    defect_description: str,
    blf_path: str | None = None,
    mf4_path: str | None = None,
    pcapng_path: str | None = None,
    ttl_path: str | None = None,
) -> AnalysisRequest:

    # ---------------------------------------------------------
    # Validate repository
    # ---------------------------------------------------------

    repo = Path(repo_path)

    if not repo.exists():
        raise ValueError(
            f"Repository path does not exist: {repo_path}"
        )

    if not repo.is_dir():
        raise ValueError(
            f"Repository path is not a directory: {repo_path}"
        )

    # ---------------------------------------------------------
    # Validate defect description
    # ---------------------------------------------------------

    if not defect_description.strip():
        raise ValueError(
            "Defect description cannot be empty."
        )

    # ---------------------------------------------------------
    # At least one input file
    # ---------------------------------------------------------

    if not any([
        blf_path,
        mf4_path,
        pcapng_path,
        ttl_path
    ]):
        raise ValueError(
            "Please provide at least one input file "
            "(BLF, MF4, PCAPNG, or TTL)."
        )

    # ---------------------------------------------------------
    # Validate provided files
    # ---------------------------------------------------------

    validated_blf = (
        validate_file(blf_path, "BLF")
        if blf_path
        else None
    )

    validated_mf4 = (
        validate_file(mf4_path, "MF4")
        if mf4_path
        else None
    )

    validated_pcapng = (
        validate_file(pcapng_path, "PCAPNG")
        if pcapng_path
        else None
    )

    validated_ttl = (
        validate_file(ttl_path, "TTL")
        if ttl_path
        else None
    )

    # ---------------------------------------------------------
    # Create request
    # ---------------------------------------------------------

    return AnalysisRequest(
        repo_path=str(repo.resolve()),
        defect_description=defect_description.strip(),
        blf_path=validated_blf,
        mf4_path=validated_mf4,
        pcapng_path=validated_pcapng,
        ttl_path=validated_ttl,
    )