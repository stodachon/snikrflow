"""Function discovery (analysis/backends/angr/functions.py)."""

from snikrflow.analysis.interfaces.functions import find_functions
from snikrflow.core.models import FunctionSource


def test_finds_named_functions_from_symbols(target1):
    by_name = {f.name: f for f in find_functions(target1)}
    for name in ("check_password", "sink_reached", "main"):
        assert name in by_name
        assert by_name[name].has_symbol
        assert by_name[name].source == FunctionSource.SYMBOL_TABLE


def test_results_are_sorted_by_address(target1):
    addrs = [f.address for f in find_functions(target1)]
    assert addrs == sorted(addrs)


def test_plt_stubs_are_labelled(target2):
    stubs = [f for f in find_functions(target2) if f.name == "strlen"]
    assert stubs and stubs[0].is_plt_stub
    assert stubs[0].source == FunctionSource.PLT_STUB


def test_angr_extern_placeholders_are_filtered_out(target2):
    # angr invents placeholder functions in a synthetic "extern" address
    # space for imports; they must never leak into results.
    main_obj = target2.project.loader.main_object
    for f in find_functions(target2):
        assert main_obj.contains_addr(f.address), f"{f.name} @ {hex(f.address)} is outside the binary"


def test_stripped_binary_still_discovers_functions(stripped, target1):
    funcs = find_functions(stripped)
    names = {f.name for f in funcs}
    assert "check_password" not in names          # symbols are gone...
    assert any(f.source == FunctionSource.ANGR_DISCOVERED for f in funcs)  # ...but angr still finds code
    assert len(funcs) >= len([f for f in find_functions(target1) if f.source == FunctionSource.SYMBOL_TABLE])


def test_repeated_discovery_is_stable(target1):
    # discover_functions() skips re-running CFGFast once kb.functions is
    # populated (audit chains several callers); results must not change.
    first = [(f.address, f.name) for f in find_functions(target1)]
    second = [(f.address, f.name) for f in find_functions(target1)]
    assert first == second
