"""
SnikrFlow angr backend -- function discovery.

This is one of the few modules allowed to touch angr's analysis objects
directly (project.analyses.CFGFast, project.kb.functions). It translates
angr's Function/CFG knowledge-base objects into SnikrFlow-owned Function
models before handing anything back up the stack.

We run CFGFast rather than CFGEmulated here -- it's the scalable option
suitable for an initial triage pass. Deeper/emulated CFG analysis is a
later milestone with its own --cfg-mode flag.
"""

from __future__ import annotations

from snikrflow.core.exceptions import AnalysisIncompleteError
from snikrflow.core.models import Function, FunctionSource
from snikrflow.elf.loader import LoadedBinary

_JNI_PREFIXES = ("Java_",)
_JNI_EXACT = ("JNI_OnLoad", "JNI_OnUnload")


def _looks_like_jni(name: str) -> bool:
    if not name:
        return False
    if name in _JNI_EXACT:
        return True
    return name.startswith(_JNI_PREFIXES)


def discover_functions(binary: LoadedBinary) -> list[Function]:
    project = binary.project
    main_obj = project.loader.main_object

    # Cross-reference lookup: address -> symbol, so we can tell whether an
    # angr-discovered function also has a name/export/import status.
    symbol_by_addr = {
        sym.rebased_addr: sym for sym in main_obj.symbols if sym.rebased_addr
    }

    try:
        if len(project.kb.functions) == 0:
            project.analyses.CFGFast(normalize=True)
        # else: CFGFast has already populated kb.functions/kb.callgraph on
        # this project (e.g. an earlier call in the same process, such as
        # `audit` chaining functions -> jni -> sinks) -- reuse it instead
        # of re-running the full analysis.
    except Exception as e:
        raise AnalysisIncompleteError(f"CFGFast analysis failed: {e}") from e

    functions: list[Function] = []

    for addr, kb_func in project.kb.functions.items():
        # angr creates synthetic placeholder functions in its own internal
        # "extern" address space to model imported functions we don't have
        # the real code for (since auto_load_libs=False). These aren't
        # real locations inside the analyzed binary, and they show up as
        # noise (e.g. appearing to call themselves) if not filtered out.
        if not main_obj.contains_addr(addr):
            continue

        name = kb_func.name or f"sub_{addr:x}"
        size = kb_func.size if kb_func.size else None

        is_plt = bool(getattr(kb_func, "is_plt", False))
        is_simprocedure = bool(getattr(kb_func, "is_simprocedure", False))

        sym = symbol_by_addr.get(addr)
        has_symbol = sym is not None
        is_imported = bool(sym.is_import) if sym else is_simprocedure
        is_exported = bool(getattr(sym, "is_export", False)) if sym else False

        if is_plt:
            source = FunctionSource.PLT_STUB
        elif is_imported:
            source = FunctionSource.IMPORT
        elif has_symbol:
            source = FunctionSource.SYMBOL_TABLE
        else:
            source = FunctionSource.ANGR_DISCOVERED

        functions.append(
            Function(
                address=addr,
                name=name,
                size=size,
                source=source,
                has_symbol=has_symbol,
                is_imported=is_imported,
                is_exported=is_exported,
                is_plt_stub=is_plt,
                is_thunk=False,  # thunk detection lands in a later milestone
                is_jni_candidate=_looks_like_jni(name),
            )
        )

    functions.sort(key=lambda f: f.address)
    return functions