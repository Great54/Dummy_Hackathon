"""Native PySide6 desktop UI for the Log Analyzer.

This module only wires up the UI and delegates all validation/business
logic to input.handler.create_analysis_request. No parsing, repository
scanning, or Gemini logic lives here.
"""

import html
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from input.handler import create_analysis_request  # noqa: E402
from input.models import AnalysisRequest  # noqa: E402
from app.worker import AnalysisWorker  # noqa: E402
from app.orchestrator.orchestrator import AnalysisOrchestrator  # noqa: E402
from app.orchestrator.evidence import AnalysisResult  # noqa: E402

logger = logging.getLogger(__name__)

# Log types the backend AnalysisRequest currently understands, mapped to the
# QFileDialog filter used when browsing for that type.
LOG_TYPES = {
    "BLF": "BLF Files (*.blf);;All Files (*)",
    "MF4": "MF4 Files (*.mf4);;All Files (*)",
    "PCAPNG": "PCAPNG Files (*.pcapng);;All Files (*)",
    "TTL": "TTL Files (*.ttl);;All Files (*)",
}

STYLESHEET = """
QWidget#central, QScrollArea { background-color: #07111f; }
QDialog { background-color: #0d1b2a; color: #e6f1ff; }
QLabel { color: #d7e5f3; }

QLabel#overline {
    color: #22d3ee;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 3px;
}
QLabel#titleLabel {
    color: #f8fafc;
    font-size: 26px;
    font-weight: 800;
}
QLabel#subtitleLabel {
    color: #8ca5ba;
    font-size: 13px;
}
QLabel#sectionLabel {
    color: #22d3ee;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 2px;
}

QFrame#header {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #07111f, stop:0.55 #0a2238, stop:1 #073b4c
    );
    border-bottom: 1px solid #164e63;
}

QFrame#statusPillReady {
    background-color: rgba(34, 197, 94, 0.15);
    border: 1px solid #22c55e;
    border-radius: 13px;
}
QFrame#statusPillUnconfigured {
    background-color: rgba(245, 158, 11, 0.12);
    border: 1px solid #f59e0b;
    border-radius: 13px;
}
QLabel#statusPillLabelReady { color: #4ade80; font-weight: 700; font-size: 12px; }
QLabel#statusPillLabelUnconfigured { color: #fbbf24; font-weight: 700; font-size: 12px; }

QFrame#card {
    background-color: #0d1b2a;
    border: 1px solid #1d3850;
    border-radius: 14px;
}
QLabel#cardTitle {
    color: #e2e8f0;
    font-size: 15px;
    font-weight: 700;
}
QLabel#cardHint {
    color: #8ca5ba;
    font-size: 12px;
}

QLineEdit, QTextEdit, QComboBox {
    background-color: #07111f;
    border: 1px solid #27445d;
    border-radius: 8px;
    color: #e2e8f0;
    padding: 8px;
    font-size: 13px;
}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
    border: 1px solid #22d3ee;
}
QTextEdit#defectEdit {
    border: 1px solid #0ea5e9;
    background-color: #081522;
    font-size: 14px;
}

QPushButton#browseButton {
    background-color: #163047;
    color: #e2e8f0;
    border: 1px solid #28516e;
    border-radius: 8px;
    padding: 8px 16px;
    font-weight: 600;
}
QPushButton#browseButton:hover { background-color: #1d4964; }

QPushButton#addLogButton {
    background-color: transparent;
    border: 2px dashed #28516e;
    border-radius: 10px;
    color: #67e8f9;
    padding: 12px;
    font-weight: 700;
}
QPushButton#addLogButton:hover {
    border-color: #22d3ee;
    color: #a5f3fc;
}

QPushButton#analyzeButton {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #0891b2
    );
    color: white;
    font-size: 16px;
    font-weight: 800;
    border-radius: 12px;
    padding: 14px 32px;
}
QPushButton#analyzeButton:hover {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0, stop:0 #0ea5e9, stop:1 #06b6d4
    );
}
QPushButton#analyzeButton:disabled {
    background: #1d3850;
    color: #64748b;
}

QFrame#logRow {
    background-color: #07111f;
    border: 1px solid #1d3850;
    border-radius: 8px;
}
QLabel#logType {
    color: #67e8f9;
    font-weight: 800;
    font-size: 12px;
}
QLabel#logName { color: #e2e8f0; font-weight: 600; font-size: 13px; }
QLabel#logPath { color: #64748b; font-size: 11px; }

QPushButton#removeButton {
    background-color: #7f1d1d;
    color: #fecaca;
    border-radius: 6px;
    padding: 4px 10px;
    font-weight: 700;
}
QPushButton#removeButton:hover { background-color: #991b1b; }

QLabel#emptyLogsLabel { color: #64748b; font-size: 12px; font-style: italic; }

QFrame#statusCard {
    background-color: #0d1b2a;
    border: 1px solid #1d3850;
    border-radius: 14px;
}
QLabel#statusText { color: #cbd5e1; font-size: 13px; }

QTextEdit#resultText {
    border: 1px solid #1d3850;
    background-color: #07111f;
    font-size: 13px;
}
QLabel#emptyResultLabel { color: #64748b; font-size: 12px; font-style: italic; }
"""


def _card(title: str, hint: Optional[str] = None) -> tuple[QFrame, QVBoxLayout]:
    """Build a rounded card frame with a title (and optional hint) header."""

    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(10)

    title_label = QLabel(title)
    title_label.setObjectName("cardTitle")
    layout.addWidget(title_label)

    if hint:
        hint_label = QLabel(hint)
        hint_label.setObjectName("cardHint")
        hint_label.setWordWrap(True)
        layout.addWidget(hint_label)

    return frame, layout


class AddLogDialog(QDialog):
    """Small dialog to pick a log type and its local file path."""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setWindowTitle("Add Log / Configuration")
        self.setMinimumWidth(420)

        self.selected_type: Optional[str] = None
        self.selected_path: Optional[str] = None

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        layout.addWidget(QLabel("Select log type"))

        self.type_combo = QComboBox()
        self.type_combo.addItem("Select log type...")
        self.type_combo.addItems(list(LOG_TYPES.keys()))
        layout.addWidget(self.type_combo)

        path_row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Select a local file...")
        browse_button = QPushButton("Browse...")
        browse_button.setObjectName("browseButton")
        browse_button.clicked.connect(self._browse)
        path_row.addWidget(self.path_edit)
        path_row.addWidget(browse_button)
        layout.addLayout(path_row)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        continue_button = QPushButton("Continue")
        continue_button.setObjectName("analyzeButton")
        continue_button.clicked.connect(self._on_continue)
        button_row.addWidget(cancel_button)
        button_row.addWidget(continue_button)
        layout.addLayout(button_row)

    def _browse(self) -> None:
        log_type = self.type_combo.currentText()
        file_filter = LOG_TYPES.get(log_type, "All Files (*)")
        file_path, _ = QFileDialog.getOpenFileName(
            self, f"Select {log_type} File", str(Path.home()), file_filter
        )
        if file_path:
            self.path_edit.setText(file_path)

    def _on_continue(self) -> None:
        log_type = self.type_combo.currentText()
        path_text = self.path_edit.text().strip()

        if log_type not in LOG_TYPES:
            QMessageBox.warning(self, "Add Log", "Please select a log type.")
            return

        if not path_text:
            QMessageBox.warning(self, "Add Log", "Please select a file.")
            return

        self.selected_type = log_type
        self.selected_path = path_text
        self.accept()


class LogAnalyzerWindow(QMainWindow):
    """Main application window for the Log Analyzer."""

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Log Analyzer")
        self.resize(900, 780)
        self.setMinimumSize(700, 600)

        self._worker: Optional[AnalysisWorker] = None
        self._analysis_worker: Optional[AnalysisWorker] = None
        self._analysis_running = False
        self._selected_logs: dict[str, str] = {}
        self._orchestrator = AnalysisOrchestrator()

        self.setStyleSheet(STYLESHEET)
        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)

        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_header())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        content.setObjectName("central")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 20, 24, 24)
        content_layout.setSpacing(16)

        section_label = QLabel("ANALYSIS INPUT")
        section_label.setObjectName("sectionLabel")
        content_layout.addWidget(section_label)

        content_layout.addWidget(self._build_repo_card())
        content_layout.addWidget(self._build_defect_card())
        content_layout.addWidget(self._build_logs_card())
        content_layout.addLayout(self._build_analyze_row())
        content_layout.addWidget(self._build_status_card())
        content_layout.addWidget(self._build_result_card())
        content_layout.addStretch(1)

        scroll.setWidget(content)
        root_layout.addWidget(scroll, stretch=1)

    def _build_header(self) -> QFrame:
        header = QFrame()
        header.setObjectName("header")

        layout = QVBoxLayout(header)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(6)

        top_row = QHBoxLayout()
        text_col = QVBoxLayout()
        text_col.setSpacing(4)

        overline = QLabel("WELCOME TO")
        overline.setObjectName("overline")
        text_col.addWidget(overline)

        title = QLabel("Trace Titans Log Analyser Agent")
        title.setObjectName("titleLabel")
        text_col.addWidget(title)

        subtitle = QLabel("AI-powered automotive log and software defect analysis")
        subtitle.setObjectName("subtitleLabel")
        text_col.addWidget(subtitle)

        top_row.addLayout(text_col, stretch=1)
        top_row.addWidget(self._build_ai_status_pill(), alignment=Qt.AlignmentFlag.AlignTop)

        layout.addLayout(top_row)
        return header

    def _build_ai_status_pill(self) -> QFrame:
        load_dotenv()
        ai_ready = bool(os.getenv("GEMINI_API_KEY"))

        pill = QFrame()
        pill.setObjectName(
            "statusPillReady" if ai_ready else "statusPillUnconfigured"
        )
        layout = QHBoxLayout(pill)
        layout.setContentsMargins(14, 6, 14, 6)

        label = QLabel(
            f"\u25cf AI ENGINE {'CONFIGURED' if ai_ready else 'NOT CONFIGURED'}"
        )
        label.setObjectName(
            "statusPillLabelReady"
            if ai_ready
            else "statusPillLabelUnconfigured"
        )
        layout.addWidget(label)
        return pill

    def _build_repo_card(self) -> QFrame:
        frame, layout = _card("\U0001F4C1  Repository")

        layout.addWidget(QLabel("Repository Path"))

        row = QHBoxLayout()
        self.repo_edit = QLineEdit()
        self.repo_edit.setPlaceholderText(r"C:\Projects\YourRepository")
        browse_button = QPushButton("Browse...")
        browse_button.setObjectName("browseButton")
        browse_button.clicked.connect(self._browse_repo)

        row.addWidget(self.repo_edit)
        row.addWidget(browse_button)
        layout.addLayout(row)

        return frame

    def _build_defect_card(self) -> QFrame:
        frame, layout = _card("\U0001F4A1  Problem Description")

        layout.addWidget(QLabel("Describe the defect / observed behaviour"))

        self.defect_edit = QTextEdit()
        self.defect_edit.setObjectName("defectEdit")
        self.defect_edit.setPlaceholderText(
            "Describe what happened, what was expected, and what was observed..."
        )
        self.defect_edit.setMinimumHeight(140)
        layout.addWidget(self.defect_edit)

        return frame

    def _build_logs_card(self) -> QFrame:
        frame, layout = _card(
            "\U0001F4CA  Analysis Logs (Optional)",
            "Select the log/configuration files you have available. "
            "None are required to start an analysis.",
        )

        add_button = QPushButton("+ Add Log / Configuration")
        add_button.setObjectName("addLogButton")
        add_button.clicked.connect(self._on_add_log)
        layout.addWidget(add_button)

        self.logs_container = QVBoxLayout()
        self.logs_container.setSpacing(8)
        layout.addLayout(self.logs_container)

        self._refresh_logs_ui()
        return frame

    def _build_analyze_row(self) -> QHBoxLayout:
        layout = QHBoxLayout()

        self.analyze_button = QPushButton("\U0001F680  START ANALYSIS")
        self.analyze_button.setObjectName("analyzeButton")
        self.analyze_button.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed
        )
        self.analyze_button.setMinimumWidth(260)
        self.analyze_button.setMinimumHeight(46)
        self.analyze_button.clicked.connect(self._on_analyze_clicked)

        layout.addStretch(1)
        layout.addWidget(self.analyze_button)
        layout.addStretch(1)
        return layout

    def _build_status_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("statusCard")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)

        title = QLabel("AI Analysis Status")
        title.setObjectName("cardTitle")
        layout.addWidget(title)

        self.status_edit = QTextEdit()
        self.status_edit.setObjectName("statusText")
        self.status_edit.setReadOnly(True)
        self.status_edit.setMaximumHeight(120)
        self.status_edit.setPlainText("\u25cf Ready to analyse")

        layout.addWidget(self.status_edit)
        return frame

    def _build_result_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("statusCard")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)

        title = QLabel("\U0001F916  AI Analysis Result")
        title.setObjectName("cardTitle")
        layout.addWidget(title)

        self.result_edit = QTextEdit()
        self.result_edit.setObjectName("resultText")
        self.result_edit.setReadOnly(True)
        self.result_edit.setMinimumHeight(160)
        self.result_edit.setHtml(
            "<i>No analysis has been run yet. Results will appear here after "
            "START ANALYSIS completes.</i>"
        )

        layout.addWidget(self.result_edit)
        return frame

    # ------------------------------------------------------------------
    # Selected logs management
    # ------------------------------------------------------------------
    def _on_add_log(self) -> None:
        dialog = AddLogDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        log_type = dialog.selected_type
        path_text = dialog.selected_path

        path = Path(path_text)
        if not path.exists() or not path.is_file():
            QMessageBox.critical(
                self, "Add Log", f"Selected {log_type} file does not exist:\n{path_text}"
            )
            return

        self._selected_logs[log_type] = str(path)
        self._refresh_logs_ui()

    def _remove_log(self, log_type: str) -> None:
        self._selected_logs.pop(log_type, None)
        self._refresh_logs_ui()

    def _refresh_logs_ui(self) -> None:
        while self.logs_container.count():
            item = self.logs_container.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        if not self._selected_logs:
            empty_label = QLabel("No logs added yet. Added files will appear here.")
            empty_label.setObjectName("emptyLogsLabel")
            self.logs_container.addWidget(empty_label)
            return

        for log_type, path_text in self._selected_logs.items():
            self.logs_container.addWidget(self._build_log_row(log_type, path_text))

    def _build_log_row(self, log_type: str, path_text: str) -> QFrame:
        path = Path(path_text)

        row = QFrame()
        row.setObjectName("logRow")
        layout = QVBoxLayout(row)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        top_row = QHBoxLayout()
        type_label = QLabel(f"\U0001F7E2 {log_type}")
        type_label.setObjectName("logType")
        name_label = QLabel(path.name)
        name_label.setObjectName("logName")

        remove_button = QPushButton("Remove")
        remove_button.setObjectName("removeButton")
        remove_button.clicked.connect(lambda: self._remove_log(log_type))

        top_row.addWidget(type_label)
        top_row.addWidget(name_label, stretch=1)
        top_row.addWidget(remove_button)
        layout.addLayout(top_row)

        path_label = QLabel(str(path))
        path_label.setObjectName("logPath")
        layout.addWidget(path_label)

        return row

    # ------------------------------------------------------------------
    # Browse handlers - native dialogs only, no file content is read here.
    # ------------------------------------------------------------------
    def _browse_repo(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self, "Select Repository Folder", self.repo_edit.text() or str(Path.home())
        )
        if directory:
            self.repo_edit.setText(directory)

    # ------------------------------------------------------------------
    # Analyze workflow: validate input, then run the orchestrator.
    # ------------------------------------------------------------------
    def _on_analyze_clicked(self) -> None:
        if self._analysis_running:
            self._cancel_analysis()
            return

        self._analysis_running = True
        self.analyze_button.setText("CANCEL ANALYSIS")
        self.status_edit.setPlainText("\u25cf Validating input...")
        self.result_edit.setHtml("<i>Analysis in progress...</i>")

        self._worker = AnalysisWorker(
            create_analysis_request,
            repo_path=self.repo_edit.text().strip(),
            defect_description=self.defect_edit.toPlainText().strip(),
            blf_path=self._selected_logs.get("BLF"),
            mf4_path=self._selected_logs.get("MF4"),
            pcapng_path=self._selected_logs.get("PCAPNG"),
            ttl_path=self._selected_logs.get("TTL"),
        )
        self._worker.succeeded.connect(self._on_validation_succeeded)
        self._worker.failed.connect(self._on_validation_failed)
        self._worker.start()

    def _on_validation_succeeded(self, request: AnalysisRequest) -> None:
        logger.info("Input validation successful for repo=%s", request.repo_path)
        self._log_status("\u25cf Input validation successful")

        self._analysis_worker = AnalysisWorker(self._orchestrator.run, request)
        self._analysis_worker.progress.connect(self._log_status)
        self._analysis_worker.succeeded.connect(self._on_analysis_succeeded)
        self._analysis_worker.failed.connect(self._on_analysis_failed)
        self._analysis_worker.finished.connect(self._finish_analysis)
        self._analysis_worker.start()

    def _on_validation_failed(self, message: str) -> None:
        logger.error("Input validation failed: %s", message)
        self._log_status(f"\u25cf Input error: {message}")
        self.result_edit.setHtml("<i>No analysis has been run yet.</i>")
        self._finish_analysis()
        QMessageBox.critical(self, "Input Error", message)

    def _on_analysis_succeeded(self, result: AnalysisResult) -> None:
        logger.info("Analysis completed with confidence=%s", result.confidence)
        self._log_status("\u25cf Analysis complete")
        self._render_result(result)

    def _on_analysis_failed(self, message: str) -> None:
        if "cancelled by the user" in message.lower():
            self._log_status("\u25cf Analysis cancelled")
            self.result_edit.setHtml("<i>Analysis cancelled.</i>")
            return
        logger.error("Analysis failed: %s", message)
        self._log_status(f"\u25cf AI analysis failed: {message}")
        self.result_edit.setHtml(
            f"<b style='color:#fca5a5;'>AI analysis failed:</b> {html.escape(message)}"
        )
        QMessageBox.critical(self, "AI Analysis Error", message)

    def _cancel_analysis(self) -> None:
        self.analyze_button.setEnabled(False)
        self._log_status("\u25cf Cancelling analysis...")
        worker = None
        if self._analysis_worker is not None and self._analysis_worker.isRunning():
            worker = self._analysis_worker
        elif self._worker is not None and self._worker.isRunning():
            worker = self._worker
        if worker is not None:
            worker.cancel()

    def _finish_analysis(self) -> None:
        self._analysis_running = False
        self.analyze_button.setText("\U0001F680  START ANALYSIS")
        self.analyze_button.setEnabled(True)

    def closeEvent(self, event) -> None:
        for worker in (self._worker, self._analysis_worker):
            if worker is not None and worker.isRunning():
                worker.cancel()
                worker.wait(3000)
        event.accept()

    def _render_result(self, result: AnalysisResult) -> None:
        def items(values: list[str]) -> str:
            if not values:
                return "<li>None</li>"
            return "".join(f"<li>{html.escape(v)}</li>" for v in values)

        if result.evidence:
            evidence_html = "".join(
                f"<li><b>[{html.escape(e.severity.upper())}] "
                f"{html.escape(e.source)}:</b> {html.escape(e.summary)}</li>"
                for e in result.evidence
            )
        else:
            evidence_html = (
                "<li>No supporting log evidence was collected for this analysis.</li>"
            )

        self.result_edit.setHtml(
            "<h2 style='color:#22d3ee;'>AI ANALYSIS</h2>"
            "<h3>Root Cause</h3>"
            f"<p>{html.escape(result.root_cause)}</p>"
            "<h3>Confidence</h3>"
            f"<p>{html.escape(result.confidence.upper())}</p>"
            "<h3>Evidence</h3>"
            f"<ul>{evidence_html}</ul>"
            "<h3>Hypotheses</h3>"
            f"<ul>{items(result.hypotheses)}</ul>"
            "<h3>Recommendation</h3>"
            f"<p>{html.escape(result.recommendation) or 'None provided.'}</p>"
            "<h3>Next Investigation Steps</h3>"
            f"<ul>{items(result.next_investigation_steps)}</ul>"
        )

    def _log_status(self, message: str) -> None:
        self.status_edit.append(message)


def run() -> int:
    logging.basicConfig(level=logging.INFO)
    app = QApplication.instance() or QApplication(sys.argv)
    window = LogAnalyzerWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(run())
