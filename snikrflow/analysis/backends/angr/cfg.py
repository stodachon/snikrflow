"""
SnikrFlow angr backend -- CFG analysis.

Supports CFGFast (default, scalable) and CFGEmulated (deeper, slower).
CFGEmulated has been deprecated/removed in some recent angr versions --
if it's unavailable here, we fail gracefully with a clear message rather
than crashing, per SnikrFlow's error-handling philosophy.
"""

from __future__ import annotations

from snikrflow.core.exceptions import AnalysisIncompleteError
from snikrflow.core.models import CFGSummary
from snikrflow.elf.loader import LoadedBinary


def build_cfg_summary(binary: LoadedBinary, mode: str = "fast") -> CFGSummary:
    project = binary.project

    if mode == "fast":
        try:
            cfg = project.analyses.CFGFast(normalize=True)
        except Exception as e:
            raise AnalysisIncompleteError(f"CFGFast failed: {e}") from e

    elif mode == "emulated":
        try:
            cfg = project.analyses.CFGEmulated(keep_state=False)
        except AttributeError as e:
            raise AnalysisIncompleteError(
                "CFGEmulated is not available in this angr version. "
                "Use --cfg-mode fast instead."
            ) from e
        except Exception as e:
            raise AnalysisIncompleteError(f"CFGEmulated failed: {e}") from e

    else:
        raise AnalysisIncompleteError(
            f"Unknown CFG mode '{mode}'. Use 'fast' or 'emulated'."
        )

    graph = cfg.graph

    return CFGSummary(
        function_count=len(project.kb.functions),
        basic_block_count=graph.number_of_nodes(),
        edge_count=graph.number_of_edges(),
        mode=mode,
    )