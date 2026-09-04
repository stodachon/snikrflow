"""
SnikrFlow angr backend -- JNI function discovery.

Reuses discover_functions() from functions.py (which runs CFGFast) rather
than re-running CFG analysis from scratch. CFGFast populates
project.kb.callgraph as a side effect, which we use here for callers/
callees -- so this stays cheap on top of an already-discovered function
set.
"""

from __future__ import annotations

from snikrflow.analysis.backends.angr.functions import discover_functions
from snikrflow.core.models import Function
from snikrflow.elf.jni import demangle_jni_name
from snikrflow.elf.loader import LoadedBinary


def discover_jni_functions(binary: LoadedBinary) -> list[Function]:
    all_functions = discover_functions(binary)  # also builds kb.callgraph

    callgraph = binary.project.kb.callgraph

    jni_functions: list[Function] = []
    for f in all_functions:
        if not f.is_jni_candidate:
            continue

        java_class, java_method = demangle_jni_name(f.name)
        f.likely_java_class = java_class
        f.likely_java_method = java_method

        try:
            f.callers = sorted(callgraph.predecessors(f.address))
        except Exception:
            f.callers = []

        try:
            f.callees = sorted(callgraph.successors(f.address))
        except Exception:
            f.callees = []

        jni_functions.append(f)

    return jni_functions