"""callers/callees and CFG summaries."""

import pytest

from snikrflow.analysis.interfaces.callgraph import find_callees, find_callers
from snikrflow.analysis.interfaces.cfg import build_cfg
from snikrflow.core.exceptions import AnalysisIncompleteError

from conftest import addr_of


def test_callers_of_sink_reached(target1):
    callers = find_callers(target1, addr_of(target1, "sink_reached"))
    assert [f.name for f in callers] == ["check_password"]


def test_callees_of_check_password(target1):
    callees = find_callees(target1, addr_of(target1, "check_password"))
    assert [f.name for f in callees] == ["sink_reached"]


def test_unknown_address_has_no_callers_or_callees(target1):
    assert find_callers(target1, 0xDEADBEEF) == []
    assert find_callees(target1, 0xDEADBEEF) == []


def test_cfg_fast_summary(target1):
    summary = build_cfg(target1, mode="fast")
    assert summary.mode == "fast"
    assert summary.function_count >= 3
    assert summary.basic_block_count >= summary.function_count
    assert summary.edge_count > 0


def test_unknown_cfg_mode_is_a_clean_error(target1):
    with pytest.raises(AnalysisIncompleteError, match="Unknown CFG mode"):
        build_cfg(target1, mode="bogus")
