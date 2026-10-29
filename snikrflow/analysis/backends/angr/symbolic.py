"""
SnikrFlow angr backend -- symbolic execution.

Places a symbolic byte buffer in memory and passes its address as the
target function's first argument (arch-agnostic, via the calling
convention's ARG_REGS), then explores toward --target while avoiding
--avoid addresses, under hard timeout/step/state-count limits.

LIMITATION: this assumes the function's first argument is a pointer to
a buffer of `input_size` bytes. It does not model JNI-specific argument
types (JNIEnv*, jobject, jstring) -- a JNI-aware symbolic setup is a
future enhancement, not this milestone.
"""

from __future__ import annotations

import time
from typing import Optional

# angr >= 10 bundles its own claripy (angr.claripy); its states only accept
# expressions built by THAT module, not by a separately installed `claripy`
# package. angr 9.x uses the standalone package. Use whichever angr uses.
try:
    from angr import claripy
except ImportError:  # angr 9.x
    import claripy

from snikrflow.core.exceptions import AnalysisIncompleteError
from snikrflow.core.models import Confidence, SolverStatus, SymbolicResult
from snikrflow.elf.loader import LoadedBinary

DEFAULT_INPUT_SIZE = 64
DEFAULT_MAX_ACTIVE_STATES = 250
DEFAULT_MAX_STEPS = 5000
DEFAULT_TIMEOUT_SECONDS = 60


def run_symbolic_search(
    binary: LoadedBinary,
    source: int,
    target: int,
    avoid: Optional[list[int]] = None,
    input_size: int = DEFAULT_INPUT_SIZE,
    max_active_states: int = DEFAULT_MAX_ACTIVE_STATES,
    max_steps: int = DEFAULT_MAX_STEPS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> SymbolicResult:
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
    # Create the result stashes up front: if exploration stops before its first
    # successful step (timeout, or an unsupported instruction raising on step one)
    # they'd otherwise not exist yet, and reading simgr.found would crash.
    simgr.populate("found", [])
    simgr.populate("avoided", [])

    start_time = time.time()
    steps_taken = 0
    stop_reason = "unknown"
    pruned = False  # True once states were dropped to respect max_active_states

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
            filter_func=lambda s: s.addr == target,
        )

        if simgr.found:
            stop_reason = "target_reached"
            break

        if len(simgr.active) > max_active_states:
            # Safety trim, not a hard stop -- keep exploring with a
            # bounded set of states rather than exploding memory use.
            # Assigning simgr.active would only shadow the stash with a plain
            # attribute (angr keeps stepping every real state) -- trim the
            # stash itself.
            simgr.stashes["active"] = simgr.stashes["active"][:max_active_states]
            pruned = True

    if stop_reason == "unknown":
        if simgr.found:
            stop_reason = "target_reached"
        elif not simgr.active:
            stop_reason = "state_limit_reached" if pruned else "no_active_states"

    if not simgr.found:
        return SymbolicResult(
            source=source, target=target, avoid=avoid,
            reachable=False, solver_status=SolverStatus.UNKNOWN,
            input_size=input_size, states_explored=steps_taken,
            stopped_reason=stop_reason,
            confidence=Confidence.INCONCLUSIVE,
            note="Target address was not reached within the configured limits.",
        )

    found_state = simgr.found[0]

    if not found_state.solver.satisfiable():
        return SymbolicResult(
            source=source, target=target, avoid=avoid,
            reachable=True, solver_status=SolverStatus.UNSAT,
            input_size=input_size, states_explored=steps_taken,
            stopped_reason=stop_reason,
            confidence=Confidence.LOW,
            note="Target was reached, but the accumulated path constraints are UNSAT.",
        )

    candidate_bytes = found_state.solver.eval(sym_input, cast_to=bytes)
    byte_constraints = [f"input[{i}] == {b:#04x}" for i, b in enumerate(candidate_bytes)]

    return SymbolicResult(
        source=source, target=target, avoid=avoid,
        reachable=True, solver_status=SolverStatus.SAT,
        candidate_input=candidate_bytes,
        input_size=input_size,
        byte_constraints=byte_constraints,
        states_explored=steps_taken,
        stopped_reason=stop_reason,
        confidence=Confidence.MEDIUM,
        note=(
            "Candidate input satisfying the path's constraints via the "
            "symbolic argument buffer. This is a CANDIDATE input, not a "
            "confirmed exploit."
        ),
    )
