"""
SnikrFlow JNI-discovery interface. CLI/GUI depend on this, not on the
angr backend directly.
"""

from __future__ import annotations

from snikrflow.analysis.backends.angr import jni as _angr_jni
from snikrflow.core.models import Function
from snikrflow.elf.loader import LoadedBinary


def find_jni_functions(binary: LoadedBinary) -> list[Function]:
    """
    Return statically-exported JNI candidate functions, enriched with a
    best-effort Java class/method guess and direct callers/callees.

    Note: this only finds statically exported JNI functions (e.g.
    Java_com_example_Foo_bar, JNI_OnLoad). Dynamically registered JNI
    methods (via RegisterNatives) cannot be reliably found through static
    analysis alone and are NOT covered here.
    """
    return _angr_jni.discover_jni_functions(binary)