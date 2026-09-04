"""
SnikrFlow sink-discovery interface. CLI/GUI depend on this, not the
angr backend directly.
"""

from __future__ import annotations

from snikrflow.analysis.backends.angr import sinks as _angr_sinks
from snikrflow.core.models import SecuritySink
from snikrflow.elf.loader import LoadedBinary


def find_sinks(binary: LoadedBinary) -> list[SecuritySink]:
    """
    Find security-sensitive function calls (memory ops, process execution,
    filesystem, networking, dynamic loading) with their callers and exact
    call-site addresses.

    Terminology note: these are "security-sensitive operations" --
    NEVER treat a sink as an automatic vulnerability finding.
    """
    return _angr_sinks.discover_sinks(binary)