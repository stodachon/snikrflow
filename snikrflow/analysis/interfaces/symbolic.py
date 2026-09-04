from __future__ import annotations

from typing import Optional

from snikrflow.analysis.backends.angr import symbolic as _angr_symbolic
from snikrflow.core.models import SymbolicResult
from snikrflow.elf.loader import LoadedBinary


def solve_symbolic(
    binary: LoadedBinary,
    source: int,
    target: int,
    avoid: Optional[list[int]] = None,
    input_size: int = _angr_symbolic.DEFAULT_INPUT_SIZE,
    max_active_states: int = _angr_symbolic.DEFAULT_MAX_ACTIVE_STATES,
    max_steps: int = _angr_symbolic.DEFAULT_MAX_STEPS,
    timeout_seconds: int = _angr_symbolic.DEFAULT_TIMEOUT_SECONDS,
) -> SymbolicResult:
    """
    Symbolically execute from `source` toward `target`, avoiding `avoid`
    addresses, with a symbolic byte buffer passed as the first argument.
    Bounded by input_size/max_active_states/max_steps/timeout_seconds.
    """
    return _angr_symbolic.run_symbolic_search(
        binary, source, target,
        avoid=avoid, input_size=input_size,
        max_active_states=max_active_states,
        max_steps=max_steps, timeout_seconds=timeout_seconds,
    )