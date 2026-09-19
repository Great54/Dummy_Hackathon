"""Native application entry point for the Log Analyzer.

Run with:

    python main.py

Launches the PySide6 desktop window directly. No Streamlit, no browser.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.gui import run  # noqa: E402


def main() -> int:
    return run()


if __name__ == "__main__":
    sys.exit(main())