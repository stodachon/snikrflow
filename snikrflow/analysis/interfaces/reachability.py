from __future__ import annotations

from snikrflow.analysis.backends.angr import reachability as _angr_reachability
from snikrflow.core.models import AnalysisPath
from snikrflow.elf.loader import LoadedBinary


def check_reachability(binary: LoadedBinary, source: int, sink: int) -> AnalysisPath:
    """
    Check STATIC (call-graph) reachability from source to sink. See
    ReachabilityType for why this is not the same as symbolic or
    runtime-verified reachability.
    """
    return _angr_reachability.check_static_reachability(binary, source, sink)