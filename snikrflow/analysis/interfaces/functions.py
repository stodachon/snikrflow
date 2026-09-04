"""
SnikrFlow function-discovery interface.

The CLI and future GUI depend on this module, never on a specific
backend. For v1 there's only one backend (angr), so this is a thin
dispatch -- but this is the seam where backend selection would happen
once Unicorn/Pin/Dyninst backends exist, without any caller needing
to change.
"""

from __future__ import annotations

from snikrflow.analysis.backends.angr import functions as _angr_functions
from snikrflow.core.models import Function
from snikrflow.elf.loader import LoadedBinary


def find_functions(binary: LoadedBinary) -> list[Function]:
    """Discover functions in the given binary, returned as SnikrFlow models."""
    return _angr_functions.discover_functions(binary)