from __future__ import annotations

from snikrflow.analysis.backends.angr import callgraph as _angr_callgraph
from snikrflow.core.models import Function
from snikrflow.elf.loader import LoadedBinary


def find_callers(binary: LoadedBinary, address: int) -> list[Function]:
    return _angr_callgraph.find_callers(binary, address)


def find_callees(binary: LoadedBinary, address: int) -> list[Function]:
    return _angr_callgraph.find_callees(binary, address)