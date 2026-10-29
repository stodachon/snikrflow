"""Symbolic execution (`solve`): candidate inputs, limits, and honest failure modes."""

from snikrflow.analysis.interfaces.symbolic import solve_symbolic
from snikrflow.core.models import Confidence, SolverStatus

from conftest import addr_of


def test_symbolic_input_reaching_target_yields_the_right_bytes(target1):
    src, tgt = addr_of(target1, "check_password"), addr_of(target1, "sink_reached")
    r = solve_symbolic(target1, src, tgt, input_size=8, timeout_seconds=60)
    assert r.reachable
    assert r.solver_status == SolverStatus.SAT
    assert r.stopped_reason == "target_reached"
    assert len(r.candidate_input) == 8
    assert r.candidate_input.startswith(b"Snik")
    assert r.byte_constraints[:4] == [
        "input[0] == 0x53", "input[1] == 0x6e", "input[2] == 0x69", "input[3] == 0x6b",
    ]


def test_candidate_input_is_labelled_as_a_candidate_not_an_exploit(target1):
    src, tgt = addr_of(target1, "check_password"), addr_of(target1, "sink_reached")
    r = solve_symbolic(target1, src, tgt, input_size=8)
    assert "candidate" in r.note.lower()
    assert "not a confirmed exploit" in r.note.lower()
    assert r.confidence == Confidence.MEDIUM


def test_input_size_is_configurable(target1):
    src, tgt = addr_of(target1, "check_password"), addr_of(target1, "sink_reached")
    assert len(solve_symbolic(target1, src, tgt, input_size=4).candidate_input) == 4
    assert len(solve_symbolic(target1, src, tgt, input_size=16).candidate_input) == 16


def test_unreachable_target_is_inconclusive_never_safe(target1):
    # Starting inside sink_reached there is no way to get to check_password.
    src, tgt = addr_of(target1, "sink_reached"), addr_of(target1, "check_password")
    r = solve_symbolic(target1, src, tgt, input_size=8)
    assert not r.reachable
    assert r.solver_status == SolverStatus.UNKNOWN
    assert r.confidence == Confidence.INCONCLUSIVE
    assert r.stopped_reason == "no_active_states"
    assert r.candidate_input is None


def test_avoid_addresses_block_the_only_path(target3):
    jni = addr_of(target3, "Java_com_example_Native_parse")
    helper = addr_of(target3, "copy_it")
    strncpy = addr_of(target3, "strncpy", plt=True)

    open_path = solve_symbolic(target3, jni, strncpy, input_size=16)
    assert open_path.reachable

    blocked = solve_symbolic(target3, jni, strncpy, avoid=[helper], input_size=16)
    assert not blocked.reachable
    assert blocked.stopped_reason == "no_active_states"


def test_step_limit_stops_exploration_and_reports_it(target1):
    src, tgt = addr_of(target1, "check_password"), addr_of(target1, "sink_reached")
    r = solve_symbolic(target1, src, tgt, input_size=8, max_steps=1)
    assert not r.reachable
    assert r.stopped_reason == "max_steps_reached"
    assert r.confidence == Confidence.INCONCLUSIVE
    assert "not reached" in r.note.lower()


def test_timeout_stops_exploration_and_reports_it(target1):
    src, tgt = addr_of(target1, "check_password"), addr_of(target1, "sink_reached")
    # A negative budget is always already exceeded -- deterministic on every
    # OS (Windows' clock is too coarse for a 0-second timeout to be reliable).
    r = solve_symbolic(target1, src, tgt, input_size=8, timeout_seconds=-1)
    assert not r.reachable
    assert r.stopped_reason == "timeout"
    assert r.confidence == Confidence.INCONCLUSIVE


def test_path_explosion_is_bounded_and_reported_inconclusive(target4):
    """
    explode() has 2^32 paths and needs well over 100 block-steps to leave its
    loop. With tiny limits the search must STOP, say why, and say INCONCLUSIVE --
    not hang, and not report the target as unreachable-therefore-safe.
    """
    src, tgt = addr_of(target4, "explode"), addr_of(target4, "sink_reached")
    r = solve_symbolic(target4, src, tgt, input_size=32, max_active_states=4, max_steps=40, timeout_seconds=120)
    assert not r.reachable
    assert r.stopped_reason == "max_steps_reached"
    assert r.solver_status == SolverStatus.UNKNOWN
    assert r.confidence == Confidence.INCONCLUSIVE


def test_state_limit_really_bounds_the_search(target4):
    """
    Regression test: trimming used to assign `simgr.active = ...`, which only
    shadowed the real stash, so max_active_states did nothing and a
    path-explosion search ate all available memory. With max_active_states=2
    this finishes in a fraction of a second. Pruning may or may not drop the
    winning path, but the result has to be honest either way.
    """
    src, tgt = addr_of(target4, "explode"), addr_of(target4, "sink_reached")
    r = solve_symbolic(target4, src, tgt, input_size=32, max_active_states=2, max_steps=2000, timeout_seconds=120)
    if r.reachable:
        assert r.solver_status == SolverStatus.SAT
        assert r.candidate_input == b"A" * 32        # the only input that satisfies all 32 branches
    else:
        assert r.stopped_reason == "state_limit_reached"
        assert r.confidence == Confidence.INCONCLUSIVE
