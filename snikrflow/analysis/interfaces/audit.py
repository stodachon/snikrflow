from __future__ import annotations

from snikrflow.analysis.backends.angr import audit as _angr_audit
from snikrflow.core.models import AuditResult
from snikrflow.elf.loader import LoadedBinary


def run_audit(binary: LoadedBinary, deep_timeout_seconds: int = 30) -> AuditResult:
    """
    Run the full triage pipeline: functions -> JNI -> sinks -> static
    reachability -> data-flow analysis on the top candidates -> ranked,
    risk-scored findings.
    """
    return _angr_audit.run_audit(binary, deep_timeout_seconds=deep_timeout_seconds)