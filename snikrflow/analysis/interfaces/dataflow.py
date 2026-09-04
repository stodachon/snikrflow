from __future__ import annotations

from typing import Optional

from snikrflow.analysis.backends.angr import dataflow as _angr_dataflow
from snikrflow.analysis.backends.angr import symbolic as _angr_symbolic
from snikrflow.core.models import DataFlowResult
from snikrflow.elf.loader import LoadedBinary


def check_data_flow(
    binary: LoadedBinary,
    source: int,
    sink: int,
    avoid: Optional[list[int]] = None,
    input_size: int = _angr_symbolic.DEFAULT_INPUT_SIZE,
    max_active_states: int = _angr_symbolic.DEFAULT_MAX_ACTIVE_STATES,
    max_steps: int = _angr_symbolic.DEFAULT_MAX_STEPS,
    timeout_seconds: int = _angr_symbolic.DEFAULT_TIMEOUT_SECONDS,
) -> DataFlowResult:
    """
    Check whether the source's symbolic input possibly influences the
    value passed into the sink. Heuristic (POSSIBLE/INCONCLUSIVE only,
    never CONFIRMED) -- see DataFlowStatus.
    """
    return _angr_dataflow.check_data_flow(
        binary, source, sink,
        avoid=avoid, input_size=input_size,
        max_active_states=max_active_states,
        max_steps=max_steps, timeout_seconds=timeout_seconds,
    )