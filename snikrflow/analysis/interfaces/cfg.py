from __future__ import annotations

from snikrflow.analysis.backends.angr import cfg as _angr_cfg
from snikrflow.core.models import CFGSummary
from snikrflow.elf.loader import LoadedBinary


def build_cfg(binary: LoadedBinary, mode: str = "fast") -> CFGSummary:
    return _angr_cfg.build_cfg_summary(binary, mode=mode)