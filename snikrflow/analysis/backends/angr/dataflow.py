"""
SnikrFlow angr backend -- data flow (heuristic taint) analysis.

Reuses the same symbolic-buffer setup as symbolic.py's run_symbolic_search,
but instead of just checking whether the sink's address is reached, we
inspect the VALUE sitting in the sink's own first argument register at
the moment execution enters it. If that value's Claripy expression
contains our "sym_input" symbolic variable, the source's data possibly
flows into what the sink operates on -- not just "control flow got
there," but "the tainted value got there."

This is a HEURISTIC, single-argument-position check, not a sound full
taint analysis (per the doc's terminology rules). It can only ever
report POSSIBLE or INCONCLUSIVE, never CONFIRMED.
"""

from __future__ import annotations

import time
from typing import Optional

import claripy

from snikrflow.analysis.backends.angr.symbolic import (
    DEFAULT_INPUT_SIZE,
    DEFAULT_MAX_ACTIVE_STATES,
    DEFAULT_MAX_STEPS,
    DEFAULT_TIMEOUT_SECONDS,
)
from snikrflow.core.exceptions import AnalysisIncompleteError
from snikrflow.core.models import Confidence, DataFlowResult, DataFlowStatus
from snikrflow.elf.loader import LoadedBinary


def check_data_flow(
    binary: LoadedBinary,
    source: int,
    sink: int,
    avoid: Optional[list[int]] = None,
    input_size: int = DEFAULT_INPUT_SIZE,
    max_active_states: int = DEFAULT_MAX_ACTIVE_STATES,
    max_steps: int = DEFAULT_MAX_STEPS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> DataFlowResult:
    project = binary.project
    avoid = avoid or []

    sym_input = claripy.BVS("sym_input", input_size * 8)

    try:
        state = project.factory.call_state(source, 0)
    except Exception as e:
        raise AnalysisIncompleteError(
            f"Failed to build a call state at {hex(source)}: {e}"
        ) from e

    try:
        buf_addr = state.heap.allocate(input_size)
        state.memory.store(buf_addr, sym_input)
        cc = project.factory.cc()
        arg_reg = cc.ARG_REGS[0]
        setattr(state.regs, arg_reg, buf_addr)
    except Exception as e:
        raise AnalysisIncompleteError(
            f"Failed to set up the symbolic argument buffer: {e}"
        ) from e

    simgr = project.factory.simgr(state)

    start_time = time.time()
    steps_taken = 0
    stop_reason = "unknown"

    while simgr.active:
        if time.time() - start_time > timeout_seconds:
            stop_reason = "timeout"
            break
        if steps_taken >= max_steps:
            stop_reason = "max_steps_reached"
            break

        try:
            simgr.step()
        except Exception:
            stop_reason = "step_error"
            break
        steps_taken += 1

        if avoid:
            simgr.move(
                from_stash="active", to_stash="avoided",
                filter_func=lambda s: s.addr in avoid,
            )

        simgr.move(
            from_stash="active", to_stash="found",
            filter_func=lambda s: s.addr == sink,
        )

        if simgr.found:
            stop_reason = "sink_reached"
            break

        if len(simgr.active) > max_active_states:
            simgr.active = simgr.active[:max_active_states]

    if stop_reason == "unknown":
        if simgr.found:
            stop_reason = "sink_reached"
        elif not simgr.active:
            stop_reason = "no_active_states"

    if not simgr.found:
        return DataFlowResult(
            source=source, sink=sink,
            status=DataFlowStatus.INCONCLUSIVE,
            confidence=Confidence.INCONCLUSIVE,
            states_explored=steps_taken, stopped_reason=stop_reason,
            note="Sink was not reached within the configured limits. This is inconclusive, not proof of safety.",
        )

    found_state = simgr.found[0]

    if not found_state.solver.satisfiable():
        return DataFlowResult(
            source=source, sink=sink,
            status=DataFlowStatus.INCONCLUSIVE,
            confidence=Confidence.LOW,
            states_explored=steps_taken, stopped_reason=stop_reason,
            note="Sink was reached, but the accumulated path constraints are UNSAT.",
        )

    # Check the sink's first few argument registers for taint. Two checks
    # per argument, since attacker data can show up either way:
    #   1. The register VALUE itself is symbolic (integer/value args, or
    #      a pointer computed via symbolic arithmetic).
    #   2. The register holds a concrete-ish pointer to memory that
    #      itself contains tainted bytes (buffer/string args -- e.g.
    #      memcpy's `src` -- where the taint lives in the pointed-to
    #      memory, not the pointer value itself).
    # We check multiple argument positions (not just arg 1) because for
    # many real sinks (memcpy, strcpy, sprintf...) the tainted data is
    # arg 2, not arg 1.
    try:
        cc = project.factory.cc()
        arg_regs = cc.ARG_REGS[:4]
    except Exception as e:
        return DataFlowResult(
            source=source, sink=sink,
            status=DataFlowStatus.INCONCLUSIVE,
            confidence=Confidence.INCONCLUSIVE,
            states_explored=steps_taken, stopped_reason=stop_reason,
            note=f"Sink was reached but its calling convention could not be resolved: {e}",
        )

    tainted = False
    tainted_arg_index: Optional[int] = None

    for idx, reg_name in enumerate(arg_regs):
        try:
            reg_value = getattr(found_state.regs, reg_name)
        except Exception:
            continue

        if any(v.startswith("sym_input") for v in reg_value.variables):
            tainted, tainted_arg_index = True, idx
            break

        if not reg_value.symbolic:
            try:
                addr = found_state.solver.eval(reg_value)
                probe = found_state.memory.load(addr, 16)
                if any(v.startswith("sym_input") for v in probe.variables):
                    tainted, tainted_arg_index = True, idx
                    break
            except Exception:
                continue

    if tainted:
        return DataFlowResult(
            source=source, sink=sink,
            status=DataFlowStatus.POSSIBLE,
            confidence=Confidence.MEDIUM,
            states_explored=steps_taken, stopped_reason=stop_reason,
            note=(
                f"Sink argument #{tainted_arg_index + 1} appears tainted by the "
                "source's symbolic input (checked both the argument value "
                "itself and, for pointer arguments, the memory it points "
                "to). Heuristic result, not a sound full taint analysis."
            ),
        )

    return DataFlowResult(
        source=source, sink=sink,
        status=DataFlowStatus.INCONCLUSIVE,
        confidence=Confidence.LOW,
        states_explored=steps_taken, stopped_reason=stop_reason,
        note=(
            "The sink was reached, but none of its first 4 arguments "
            "(register value or pointed-to memory) appear derived from "
            "the source's symbolic input. Note: a sink that takes no "
            "arguments (a bare marker/flag function) will always show "
            "this result -- there's nothing for it to receive."
        ),
    )