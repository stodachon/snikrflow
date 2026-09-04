"""
SnikrFlow exceptions.

Every operational failure (malformed binary, unsupported arch, angr choking
on something) should surface as one of these -- never as a raw traceback
in front of the user. The CLI layer catches SnikrFlowError and prints a
clean [!] message instead.
"""

from __future__ import annotations


class SnikrFlowError(Exception):
    """Base class for all SnikrFlow errors."""


class BinaryLoadError(SnikrFlowError):
    """Raised when a binary can't be loaded at all (missing, malformed, etc.)."""


class UnsupportedArchitectureError(SnikrFlowError):
    """Raised when the binary's architecture isn't one we support yet."""


class AnalysisTimeoutError(SnikrFlowError):
    """Raised when an analysis stage exceeds its configured time budget."""


class AnalysisIncompleteError(SnikrFlowError):
    """
    Raised (or caught and converted into a finding with INCONCLUSIVE
    confidence) when an analysis stage had to stop early -- state
    explosion, path limits, unsupported instructions, etc.

    Important: this should never be silently treated as "safe" or "clean".
    """