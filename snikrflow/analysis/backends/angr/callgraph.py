"""
SnikrFlow angr backend -- callers/callees lookup.

Reuses discover_functions() (runs CFGFast, builds kb.callgraph) so
callers/callees work off the same function set as `functions`/`jni`/
`sinks` -- no separate, possibly-inconsistent analysis pass.
"""

from __future__ import annotations

from snikrflow.analysis.backends.angr.functions import discover_functions
from snikrflow.core.models import Function
from snikrflow.elf.loader import LoadedBinary


def _resolve(binary: LoadedBinary):
    all_functions = discover_functions(binary)
    by_addr = {f.address: f for f in all_functions}
    callgraph = binary.project.kb.callgraph
    return by_addr, callgraph


def find_callers(binary: LoadedBinary, address: int) -> list[Function]:
    """Direct callers of the function at `address`. Indirect/unresolved calls are not included."""
    by_addr, callgraph = _resolve(binary)
    try:
        caller_addrs = sorted(callgraph.predecessors(address))
    except Exception:
        caller_addrs = []
    return [by_addr[a] for a in caller_addrs if a in by_addr]


def find_callees(binary: LoadedBinary, address: int) -> list[Function]:
    """Direct callees of the function at `address`. Indirect/unresolved calls are not included."""
    by_addr, callgraph = _resolve(binary)
    try:
        callee_addrs = sorted(callgraph.successors(address))
    except Exception:
        callee_addrs = []
    return [by_addr[a] for a in callee_addrs if a in by_addr]