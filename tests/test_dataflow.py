"""Heuristic data-flow (taint) check."""

import pytest

from snikrflow.analysis.interfaces.dataflow import check_data_flow
from snikrflow.core.models import Confidence, DataFlowStatus

from conftest import addr_of


def test_buffer_pointer_flowing_into_sink_argument_is_possible(target2):
    # relay(buf) -> strlen(buf): the pointer is concrete, but it points at
    # symbolic (tainted) memory -- the case that needs pointer dereferencing.
    r = check_data_flow(target2, addr_of(target2, "relay"), addr_of(target2, "strlen", plt=True))
    assert r.status == DataFlowStatus.POSSIBLE
    assert r.confidence == Confidence.MEDIUM


def test_taint_through_a_wrapper_into_a_memory_sink(target3):
    # buf -> copy_it -> strncpy(local, buf, 8): tainted data is argument #2.
    r = check_data_flow(
        target3, addr_of(target3, "Java_com_example_Native_parse"), addr_of(target3, "strncpy", plt=True)
    )
    assert r.status == DataFlowStatus.POSSIBLE


def test_unreached_sink_is_inconclusive(target1):
    r = check_data_flow(target1, addr_of(target1, "sink_reached"), addr_of(target1, "check_password"))
    assert r.status == DataFlowStatus.INCONCLUSIVE
    assert r.confidence == Confidence.INCONCLUSIVE
    assert "not proof of safety" in r.note.lower()


def test_dataflow_never_claims_confirmed(target1, target2, target3):
    cases = [
        (target1, "check_password", "sink_reached", False),
        (target2, "relay", "strlen", True),
        (target3, "Java_com_example_Native_parse", "strncpy", True),
    ]
    for binary, src, sink, plt in cases:
        r = check_data_flow(binary, addr_of(binary, src), addr_of(binary, sink, plt=plt))
        assert r.status != DataFlowStatus.CONFIRMED   # reserved for stronger evidence than a heuristic


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN FALSE POSITIVE: sink_reached() takes no arguments, but check_password's "
        "buffer pointer is still sitting in the first argument register when it is "
        "entered, and the heuristic can't tell a leftover register from a real argument."
    ),
)
def test_sink_without_arguments_should_not_look_tainted(target1):
    r = check_data_flow(target1, addr_of(target1, "check_password"), addr_of(target1, "sink_reached"))
    assert r.status == DataFlowStatus.INCONCLUSIVE
