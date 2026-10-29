"""Static (call-graph) reachability."""

from snikrflow.analysis.interfaces.reachability import check_reachability
from snikrflow.core.models import Confidence, ReachabilityType

from conftest import addr_of


def test_direct_call_is_statically_reachable(target1):
    src, sink = addr_of(target1, "check_password"), addr_of(target1, "sink_reached")
    r = check_reachability(target1, src, sink)
    assert r.reachable
    assert r.reachability_type == ReachabilityType.STATICALLY_REACHABLE
    assert r.function_path == [src, sink]
    assert r.path_labels[0].startswith("check_password @ ")


def test_multi_hop_path_lists_every_function(target1):
    main, check, sink = (addr_of(target1, n) for n in ("main", "check_password", "sink_reached"))
    r = check_reachability(target1, main, sink)
    assert r.reachable
    assert r.function_path == [main, check, sink]


def test_wrapper_chain_to_a_dangerous_sink(target3):
    jni = addr_of(target3, "Java_com_example_Native_parse")
    helper = addr_of(target3, "copy_it")
    strncpy = addr_of(target3, "strncpy", plt=True)
    r = check_reachability(target3, jni, strncpy)
    assert r.reachable
    assert r.function_path == [jni, helper, strncpy]


def test_reverse_direction_is_not_reachable_and_says_it_is_not_proof(target1):
    src, sink = addr_of(target1, "check_password"), addr_of(target1, "sink_reached")
    r = check_reachability(target1, sink, src)
    assert not r.reachable
    assert r.reachability_type == ReachabilityType.NOT_REACHABLE
    assert "does not prove" in r.note.lower() and "indirect" in r.note.lower()


def test_unknown_addresses_are_inconclusive_not_unreachable(target1):
    good = addr_of(target1, "main")
    for src, sink in ((0xDEADBEEF, good), (good, 0xDEADBEEF)):
        r = check_reachability(target1, src, sink)
        assert not r.reachable
        assert r.reachability_type == ReachabilityType.INCONCLUSIVE
        assert r.confidence == Confidence.INCONCLUSIVE


def test_function_reaches_itself_with_high_confidence(target1):
    main = addr_of(target1, "main")
    r = check_reachability(target1, main, main)
    assert r.reachable and r.function_path == [main]
    assert r.confidence == Confidence.HIGH


def test_unresolved_indirect_call_is_a_false_negative_not_a_safe_verdict(target5):
    """
    KNOWN LIMITATION, pinned on purpose. At runtime main() DOES end up running
    sink_reached() (it passes it to run_callback, which calls it through a
    pointer), but the call graph has no such edge. The result must be
    NOT_REACHABLE *with the caveat*, and must never be presented as "safe".
    If angr (or SnikrFlow) starts resolving this, update this test and the
    README's limitations section.
    """
    main, sink = addr_of(target5, "main"), addr_of(target5, "sink_reached")
    r = check_reachability(target5, main, sink)
    assert r.reachability_type == ReachabilityType.NOT_REACHABLE
    assert "indirect" in r.note.lower()
    # ...while the direct edge that does exist is found:
    assert check_reachability(target5, main, addr_of(target5, "run_callback")).reachable
