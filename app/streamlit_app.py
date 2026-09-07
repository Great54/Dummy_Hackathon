import streamlit as st
from pathlib import Path

from input.handler import create_analysis_request


# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------

st.set_page_config(
    page_title="Log Analyzer",
    page_icon="🔍",
    layout="wide"
)


# ---------------------------------------------------------
# Header
# ---------------------------------------------------------

st.title("🔍 Log Analyzer")

st.markdown(
    """
    Analyze software and communication defects using your repository
    and available log/configuration files.
    """
)

st.divider()


# ---------------------------------------------------------
# Repository Input
# ---------------------------------------------------------

st.subheader("1. Repository")

repo_path = st.text_input(
    "Repository Path",
    placeholder="/workspaces/your-repository",
    help="Enter the local path of the repository to be analyzed."
)


# ---------------------------------------------------------
# Defect Description
# ---------------------------------------------------------

st.subheader("2. Defect / Problem Description")

defect_description = st.text_area(
    "Describe the problem",
    placeholder=(
        "Example:\n"
        "SOME/IP request is sent but the expected response "
        "is not received after KL15 ON."
    ),
    height=180,
    help=(
        "Describe the observed problem. Include expected behavior, "
        "actual behavior, and any useful details."
    )
)


# ---------------------------------------------------------
# Input Files
# ---------------------------------------------------------

st.subheader("3. Input Files")

st.caption(
    "Upload any available files. All files are optional, "
    "but at least one file is required for analysis."
)

col1, col2 = st.columns(2)

with col1:

    blf_file = st.file_uploader(
        "BLF File",
        type=["blf"],
        help="Upload a BLF trace file."
    )

    mf4_file = st.file_uploader(
        "MF4 File",
        type=["mf4"],
        help="Upload an MF4 measurement file."
    )


with col2:

    pcapng_file = st.file_uploader(
        "PCAPNG File",
        type=["pcapng"],
        help="Upload a PCAPNG network capture."
    )

    ttl_file = st.file_uploader(
        "TTL File",
        type=["ttl"],
        help="Upload a TTL configuration file."
    )


# ---------------------------------------------------------
# Selected Files
# ---------------------------------------------------------

selected_files = []

if blf_file:
    selected_files.append(("BLF", blf_file.name))

if mf4_file:
    selected_files.append(("MF4", mf4_file.name))

if pcapng_file:
    selected_files.append(("PCAPNG", pcapng_file.name))

if ttl_file:
    selected_files.append(("TTL", ttl_file.name))


if selected_files:

    st.subheader("Selected Files")

    for file_type, file_name in selected_files:
        st.success(f"{file_type}: {file_name}")

else:

    st.info("No files selected.")


st.divider()


# ---------------------------------------------------------
# Analyze Button
# ---------------------------------------------------------

analyze_clicked = st.button(
    "🚀 Analyze",
    type="primary",
    use_container_width=True
)


# ---------------------------------------------------------
# Process Analysis Request
# ---------------------------------------------------------

if analyze_clicked:

    # Basic validation
    if not repo_path.strip():

        st.error("Please enter the repository path.")

    elif not defect_description.strip():

        st.error("Please provide a defect/problem description.")

    elif not selected_files:

        st.error(
            "Please upload at least one file "
            "(BLF, MF4, PCAPNG, or TTL)."
        )

    else:

        # Temporary directory for uploaded files
        temp_dir = Path("data/temp")
        temp_dir.mkdir(parents=True, exist_ok=True)

        # Initialize paths
        blf_path = None
        mf4_path = None
        pcapng_path = None
        ttl_path = None

        # Save BLF
        if blf_file:

            blf_path = temp_dir / blf_file.name
            blf_path.write_bytes(blf_file.getbuffer())

        # Save MF4
        if mf4_file:

            mf4_path = temp_dir / mf4_file.name
            mf4_path.write_bytes(mf4_file.getbuffer())

        # Save PCAPNG
        if pcapng_file:

            pcapng_path = temp_dir / pcapng_file.name
            pcapng_path.write_bytes(pcapng_file.getbuffer())

        # Save TTL
        if ttl_file:

            ttl_path = temp_dir / ttl_file.name
            ttl_path.write_bytes(ttl_file.getbuffer())

        # Create analysis request
        try:

            request = create_analysis_request(
                repo_path=repo_path,
                defect_description=defect_description,
                blf_path=str(blf_path) if blf_path else None,
                mf4_path=str(mf4_path) if mf4_path else None,
                pcapng_path=str(pcapng_path) if pcapng_path else None,
                ttl_path=str(ttl_path) if ttl_path else None,
            )

            st.success("Input validation successful!")

            # -------------------------------------------------
            # Display Analysis Request
            # -------------------------------------------------

            st.subheader("Analysis Request")

            st.json(
                {
                    "repository": request.repo_path,
                    "defect_description": request.defect_description,
                    "blf": request.blf_path,
                    "mf4": request.mf4_path,
                    "pcapng": request.pcapng_path,
                    "ttl": request.ttl_path,
                }
            )

            # -------------------------------------------------
            # Placeholder for Agent
            # -------------------------------------------------

            st.info(
                "The input stage is ready. "
                "The AI analysis agent will be connected next."
            )

        except ValueError as error:

            st.error(f"Input Error: {error}")