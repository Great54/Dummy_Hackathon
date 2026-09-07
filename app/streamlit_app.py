import sys
from pathlib import Path

import streamlit as st


# ---------------------------------------------------------
# Add project root to Python path
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


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
    Analyze software and communication defects using your
    local repository and available log/configuration files.
    """
)

st.divider()


# ---------------------------------------------------------
# Repository
# ---------------------------------------------------------

st.subheader("1. Repository")

repo_path = st.text_input(
    "Repository Path",
    placeholder="C:\\Projects\\YourRepository",
    help="Enter the local path of the repository to analyze."
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
        "Describe what happened, what was expected, "
        "and what was actually observed."
    )
)


# ---------------------------------------------------------
# Input Files
# ---------------------------------------------------------

st.subheader("3. Input Files")

st.caption(
    "Select the file type and provide the local path. "
    "You can add multiple files."
)


# Initialize selected files
if "selected_files" not in st.session_state:
    st.session_state.selected_files = {}


# ---------------------------------------------------------
# File Type
# ---------------------------------------------------------

file_type = st.selectbox(
    "Select File Type",
    [
        "BLF",
        "MF4",
        "PCAPNG",
        "TTL"
    ]
)


# ---------------------------------------------------------
# File Path
# ---------------------------------------------------------

file_path = st.text_input(
    f"{file_type} File Path",
    placeholder=f"C:\\Logs\\example.{file_type.lower()}",
    help="Enter the complete local path to the file."
)


# ---------------------------------------------------------
# Add File
# ---------------------------------------------------------

if st.button("➕ Add File"):

    if not file_path.strip():

        st.error(
            f"Please enter the path to the {file_type} file."
        )

    else:

        path = Path(file_path.strip())

        if not path.exists():

            st.error(
                f"File does not exist:\n{file_path}"
            )

        elif not path.is_file():

            st.error(
                f"The provided path is not a file:\n{file_path}"
            )

        else:

            st.session_state.selected_files[file_type] = (
                str(path.resolve())
            )

            st.success(
                f"{file_type} file added successfully."
            )


# ---------------------------------------------------------
# Selected Files
# ---------------------------------------------------------

if st.session_state.selected_files:

    st.markdown("### Selected Files")

    for selected_type, selected_path in list(
        st.session_state.selected_files.items()
    ):

        col1, col2 = st.columns([5, 1])

        with col1:

            st.text_input(
                selected_type,
                value=selected_path,
                disabled=True,
                key=f"display_{selected_type}"
            )

        with col2:

            if st.button(
                "Remove",
                key=f"remove_{selected_type}"
            ):

                del st.session_state.selected_files[
                    selected_type
                ]

                st.rerun()

else:

    st.info("No input files selected.")


st.divider()


# ---------------------------------------------------------
# Analyze
# ---------------------------------------------------------

if st.button(
    "🚀 Analyze",
    type="primary",
    use_container_width=True
):

    # Basic validation

    if not repo_path.strip():

        st.error(
            "Please enter the repository path."
        )

    elif not defect_description.strip():

        st.error(
            "Please provide a defect/problem description."
        )

    elif not st.session_state.selected_files:

        st.error(
            "Please add at least one input file."
        )

    else:

        selected_files = st.session_state.selected_files

        # Get paths by type

        blf_path = selected_files.get("BLF")
        mf4_path = selected_files.get("MF4")
        pcapng_path = selected_files.get("PCAPNG")
        ttl_path = selected_files.get("TTL")

        try:

            request = create_analysis_request(
                repo_path=repo_path,
                defect_description=defect_description,
                blf_path=blf_path,
                mf4_path=mf4_path,
                pcapng_path=pcapng_path,
                ttl_path=ttl_path,
            )

            st.success(
                "Input validation successful!"
            )

            # -------------------------------------------------
            # Display Request
            # -------------------------------------------------

            st.subheader("Analysis Request")

            st.json(
                {
                    "repository": request.repo_path,
                    "defect_description": (
                        request.defect_description
                    ),
                    "blf": request.blf_path,
                    "mf4": request.mf4_path,
                    "pcapng": request.pcapng_path,
                    "ttl": request.ttl_path,
                }
            )

            st.info(
                "Input stage completed successfully. "
                "The analysis agent will be connected next."
            )

        except ValueError as error:

            st.error(
                f"Input Error: {error}"
            )