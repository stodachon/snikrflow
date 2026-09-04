"""
SnikrFlow ELF metadata extraction.

Turns a LoadedBinary (angr project handle) into a SnikrFlow BinaryInfo
model. We reuse angr's CLE loader (project.loader.main_object) for most
facts since the binary is already loaded once -- no reason to parse it
twice. The ELF header's e_type (ET_DYN / ET_EXEC / etc.) is pulled via
pyelftools directly instead, since CLE's attribute name for this has
proven to vary across versions and pyelftools is a stable, dedicated
dependency for exactly this kind of low-level ELF detail.
"""

from __future__ import annotations

from elftools.elf.elffile import ELFFile

from snikrflow.core.models import BinaryInfo
from snikrflow.elf.loader import LoadedBinary

# Cheap heuristic for JNI candidates at the `info` stage. This is NOT the
# full JNI analysis engine (that's a later milestone) -- just a fast
# symbol-name scan so `info` can give a useful at-a-glance number.
_JNI_PREFIXES = ("Java_",)
_JNI_EXACT = ("JNI_OnLoad", "JNI_OnUnload")


def _looks_like_jni(name: str) -> bool:
    if not name:
        return False
    if name in _JNI_EXACT:
        return True
    return name.startswith(_JNI_PREFIXES)


def _read_elf_type(binary: LoadedBinary) -> str:
    """Read e_type directly via pyelftools. Returns e.g. 'ET_DYN', 'ET_EXEC'."""
    try:
        with open(binary.path, "rb") as f:
            elffile = ELFFile(f)
            return elffile.header["e_type"]
    except Exception:
        return "UNKNOWN"


def extract_binary_info(binary: LoadedBinary) -> BinaryInfo:
    main_obj = binary.project.loader.main_object

    symbols = list(main_obj.symbols)
    function_symbols = [s for s in symbols if s.is_function and s.name]
    defined_function_symbols = [s for s in function_symbols if not s.is_import]
    export_symbols = [s for s in symbols if getattr(s, "is_export", False)]

    # Heuristic: if there are no defined (non-imported) function symbols
    # with names, the binary has almost certainly had its symtab stripped.
    is_stripped = len(defined_function_symbols) == 0

    jni_candidates = sum(1 for s in symbols if _looks_like_jni(s.name))

    try:
        shared_deps = list(main_obj.deps)
    except AttributeError:
        shared_deps = []

    elf_type = _read_elf_type(binary)
    is_shared_object = elf_type == "ET_DYN"

    return BinaryInfo(
        path=binary.path,
        architecture=binary.architecture,
        endianness=binary.endianness,
        bitness=binary.bitness,
        elf_type=elf_type,
        entry_point=main_obj.entry,
        is_shared_object=is_shared_object,
        is_stripped=is_stripped,
        section_count=len(main_obj.sections),
        segment_count=len(main_obj.segments),
        symbol_count=len(symbols),
        import_count=len(main_obj.imports),
        export_count=len(export_symbols),
        shared_deps=shared_deps,
        function_count=len(function_symbols),
        jni_candidate_count=jni_candidates,
    )