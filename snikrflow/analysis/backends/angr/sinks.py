"""
SnikrFlow angr backend -- security sink discovery.

Reuses discover_functions() (which runs CFGFast and populates
kb.callgraph) rather than re-running CFG analysis. For each function
whose name matches a known sink signature, we walk its callers via the
call graph, then use angr's per-function call-site data
(kb.functions[caller].get_call_sites()) to find the EXACT address of
each call instruction -- not just "this function calls that function"
but the specific site, which is what a researcher actually needs to
jump to in Ghidra.
"""

from __future__ import annotations

from snikrflow.analysis.backends.angr.functions import discover_functions
from snikrflow.core.models import SecuritySink, SinkCallSite
from snikrflow.elf.loader import LoadedBinary
from snikrflow.sinks.database import lookup_category


def discover_sinks(binary: LoadedBinary) -> list[SecuritySink]:
    all_functions = discover_functions(binary)  # also builds kb.callgraph
    by_addr = {f.address: f for f in all_functions}

    callgraph = binary.project.kb.callgraph
    kb_functions = binary.project.kb.functions

    sinks: list[SecuritySink] = []

    for f in all_functions:
        category = lookup_category(f.name)
        if category is None:
            continue

        sink = SecuritySink(
            address=f.address,
            name=f.name,
            category=category,
            is_imported=f.is_imported,
        )

        try:
            caller_addrs = sorted(callgraph.predecessors(f.address))
        except Exception:
            caller_addrs = []

        for caller_addr in caller_addrs:
            caller_func = by_addr.get(caller_addr)
            caller_name = caller_func.name if caller_func else f"sub_{caller_addr:x}"

            call_site_addrs: list[int] = []
            try:
                kb_caller = kb_functions.get(caller_addr)
                if kb_caller is not None:
                    for site in kb_caller.get_call_sites():
                        target = kb_caller.get_call_target(site)
                        if target == f.address:
                            call_site_addrs.append(site)
            except Exception:  # noqa: BLE001, S110
                pass

            sink.call_sites.append(
                SinkCallSite(
                    caller_address=caller_addr,
                    caller_name=caller_name,
                    call_site_addresses=sorted(call_site_addrs),
                )
            )

        sinks.append(sink)

    sinks.sort(key=lambda s: s.address)
    return sinks