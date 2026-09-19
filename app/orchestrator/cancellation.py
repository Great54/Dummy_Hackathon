"""Shared cancellation exception for background analysis operations."""


class AnalysisCancelledError(RuntimeError):
    """Raised when the user cancels an active analysis."""
