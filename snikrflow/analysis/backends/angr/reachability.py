"""
SnikrFlow angr backend -- static reachability.

Static reachability here means call-graph reachability: is there a chain
of DIRECT calls from source to sink? This only sees direct calls -- it
does NOT track indirect calls (function pointers, vtables, etc.), so a
"not reachable" result is never proof of safety, only "no direct call
chain found." Symbolic/data-flow reachability (later milestones) goes
further; runtime verification goes further still. These are never
treated as equivalent, per SnikrFlow's terminology rules.
"""

from __future__ import annotations

import networkx as nx

from snikrflow.analysis.backends.angr.functions import discover_functions
from snikrflow.core.models import AnalysisPath, Confidence, ReachabilityType
from snikrflow.elf.loader import LoadedBinary


def check_static_reachability(binary: LoadedBinary, source: int, sink: int) -> AnalysisPath:
    all_functions = discover_functions(binary)
    by_addr = {f.address: f for f in all_functions}
    callgraph = binary.project.kb.callgraph

    if source not in by_addr:
        return AnalysisPath(
            source=source, sink=sink, reachable=False,
            reachability_type=ReachabilityType.INCONCLUSIVE,
            confidence=Confidence.INCONCLUSIVE,
            note=f"Source address {hex(source)} is not a known function start.",
        )
    if sink not in by_addr:
        return AnalysisPath(
            source=source, sink=sink, reachable=False,
            reachability_type=ReachabilityType.INCONCLUSIVE,
            confidence=Confidence.INCONCLUSIVE,
            note=f"Sink address {hex(sink)} is not a known function start.",
        )

    if source == sink:
        label = f"{by_addr[source].name} @ {hex(source)}"
        return AnalysisPath(
            source=source, sink=sink, reachable=True,
            reachability_type=ReachabilityType.STATICALLY_REACHABLE,
            function_path=[source], path_labels=[label],
            confidence=Confidence.HIGH,
            note="Source and sink are the same function.",
        )

    try:
        path = nx.shortest_path(callgraph, source=source, target=sink)
    except nx.NetworkXNoPath:
        return AnalysisPath(
            source=source, sink=sink, reachable=False,
            reachability_type=ReachabilityType.NOT_REACHABLE,
            confidence=Confidence.MEDIUM,
            note=(
                "No direct call-graph path found. This does NOT prove the "
                "sink is unreachable -- indirect calls (function pointers, "
                "vtables) aren't tracked by this analysis."
            ),
        )
    except nx.NodeNotFound:
        return AnalysisPath(
            source=source, sink=sink, reachable=False,
            reachability_type=ReachabilityType.INCONCLUSIVE,
            confidence=Confidence.INCONCLUSIVE,
            note="Source or sink address not present in the call graph.",
        )

    labels = [
        f"{by_addr[a].name if a in by_addr else f'sub_{a:x}'} @ {hex(a)}"
        for a in path
    ]

    return AnalysisPath(
        source=source, sink=sink, reachable=True,
        reachability_type=ReachabilityType.STATICALLY_REACHABLE,
        function_path=path, path_labels=labels,
        confidence=Confidence.MEDIUM,
        note="Based on direct call-graph edges only; indirect/unresolved calls not tracked.",
    )