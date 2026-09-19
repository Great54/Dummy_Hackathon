"""Background worker infrastructure so the GUI never blocks on analysis work."""

import inspect
from typing import Any, Callable

from PySide6.QtCore import QThread, Signal


class AnalysisWorker(QThread):
    """Runs a callable off the GUI thread and reports the outcome via signals."""

    succeeded = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, target: Callable[..., Any], *args: Any, **kwargs: Any):
        super().__init__()
        self._target = target
        self._args = args
        self._kwargs = kwargs

    def run(self) -> None:
        try:
            kwargs = dict(self._kwargs)
            if "on_progress" not in kwargs and self._target_accepts_progress():
                kwargs["on_progress"] = self.progress.emit
            result = self._target(*self._args, **kwargs)
        except Exception as error:  # noqa: BLE001 - surfaced to the UI as text
            self.failed.emit(str(error))
        else:
            if self.isInterruptionRequested():
                self.failed.emit("Analysis cancelled by the user.")
            else:
                self.succeeded.emit(result)

    def cancel(self) -> None:
        self.requestInterruption()
        owner = getattr(self._target, "__self__", None)
        if owner is not None and hasattr(owner, "cancel"):
            owner.cancel()

    def _target_accepts_progress(self) -> bool:
        try:
            params = inspect.signature(self._target).parameters
        except (TypeError, ValueError):
            return False
        return "on_progress" in params

