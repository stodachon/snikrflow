"""
SnikrFlow angr backend -- audit orchestration.

Combines every prior analysis stage into one pipeline, per the doc's
performance philosophy: cheap triage on everything, expensive symbolic/
data-flow analysis only on the most promising candidates.

Pipeline:
  1. Discover functions, JNI candidates, sinks (cheap -- one CFGFast run,
     reused across all three thanks to the caching guard in functions.py).
  2. For every (JNI entry, sink) pair, check STATIC call-graph
     reachability (cheap -- no symbolic execution).
  3. Rank the statically-reachable pairs by call-chain length (shorter =
     more direct = higher priority) and take the top N for deep analysis.
  4. Run data-flow analysis (symbolic, bounded by a short per-pair
     timeout) ONLY on that top-N subset.
  5. Score risk transparently (see _score_risk) and sort findings by risk.
"""

from __future__ import annotations

from typing import Optional

from snikrflow.analysis.backends.angr.dataflow import check_data_flow
from snikrflow.analysis.backends.angr.functions import discover_functions
from snikrflow.analysis.backends.angr.jni import discover_jni_functions
from snikrflow.analysis.backends.angr.reachability import check_static_reachability
from snikrflow.analysis.backends.angr.sinks import discover_sinks
from snikrflow.core.models import (
    AnalysisFinding,
    AuditResult,
    DataFlowStatus,
    ReachabilityType,
    RiskLevel,
)
from snikrflow.elf.loader import LoadedBinary
from snikrflow.elf.metadata import extract_binary_info

# Cap on how many statically-reachable pairs get the expensive data-flow
# treatment. Keeps `audit` bounded on binaries with many JNI x sink
# combinations -- deep analysis is a scarce resource, spent on the most
# direct (shortest) paths first.
MAX_DEEP_ANALYSIS_PAIRS = 5
DEFAULT_DEEP_TIMEOUT_SECONDS = 30

# Rough, documented, and DELIBERATELY simple severity weighting per sink
# category. This is a transparent prioritization heuristic, not a
# vulnerability database -- edit freely.
_CATEGORY_SEVERITY = {
    "process_execution": 3,
    "dynamic_loading": 3,
    "memory": 2,
    "networking": 2,
    "filesystem": 1,
}


def _score_risk(
    reachability_type: ReachabilityType,
    data_flow_status: Optional[DataFlowStatus],
    category: str,
) -> RiskLevel:
    severity = _CATEGORY_SEVERITY.get(category, 1)

    if reachability_type != ReachabilityType.STATICALLY_REACHABLE:
        return RiskLevel.LOW

    if data_flow_status == DataFlowStatus.POSSIBLE:
        return RiskLevel.CRITICAL if severity >= 3 else RiskLevel.HIGH

    # Reachable via call graph, but data flow wasn't confirmed possible
    # (either not checked, or checked and came back inconclusive).
    return RiskLevel.HIGH if severity >= 3 else RiskLevel.MEDIUM


def run_audit(binary: LoadedBinary, deep_timeout_seconds: int = DEFAULT_DEEP_TIMEOUT_SECONDS) -> AuditResult:
    binary_info = extract_binary_info(binary)

    all_functions = discover_functions(binary)      # runs CFGFast once
    jni_functions = discover_jni_functions(binary)   # reuses it
    sinks = discover_sinks(binary)                   # reuses it

    # Step 1: cheap static reachability across every JNI x sink pair.
    reachable_pairs = []
    for jni_func in jni_functions:
        for sink in sinks:
            path = check_static_reachability(binary, jni_func.address, sink.address)
            if path.reachable and path.reachability_type == ReachabilityType.STATICALLY_REACHABLE:
                reachable_pairs.append((jni_func, sink, path))

    # Step 2: prioritize shortest (most direct) call chains for deep analysis.
    reachable_pairs.sort(key=lambda item: len(item[2].function_path))
    deep_pairs = reachable_pairs[:MAX_DEEP_ANALYSIS_PAIRS]
    deep_keys = {(j.address, s.address) for j, s, _ in deep_pairs}

    # Step 3: build findings, running data-flow only on the selected subset.
    findings: list[AnalysisFinding] = []
    for jni_func, sink, path in reachable_pairs:
        data_flow_status: Optional[DataFlowStatus] = None
        confidence = path.confidence
        notes: list[str] = [path.note] if path.note else []

        if (jni_func.address, sink.address) in deep_keys:
            try:
                df_result = check_data_flow(
                    binary, jni_func.address, sink.address,
                    timeout_seconds=deep_timeout_seconds,
                )
                data_flow_status = df_result.status
                confidence = df_result.confidence
                if df_result.note:
                    notes.append(df_result.note)
            except Exception as e:
                notes.append(f"Data-flow analysis failed: {e}")

        risk = _score_risk(path.reachability_type, data_flow_status, sink.category)

        findings.append(
            AnalysisFinding(
                title=f"JNI -> {sink.category}",
                source_address=jni_func.address,
                source_name=jni_func.name,
                sink_address=sink.address,
                sink_name=sink.name,
                sink_category=sink.category,
                reachability_type=path.reachability_type,
                data_flow_status=data_flow_status,
                risk_level=risk,
                confidence=confidence,
                notes=notes,
            )
        )

    risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3}
    findings.sort(key=lambda f: risk_order.get(f.risk_level, 4))

    return AuditResult(
        binary_info=binary_info,
        function_count=len(all_functions),
        jni_count=len(jni_functions),
        sink_count=len(sinks),
        interesting_path_count=len(reachable_pairs),
        symbolic_analysis_count=len(deep_pairs),
        findings=findings,
    )