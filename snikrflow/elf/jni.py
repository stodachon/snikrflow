"""
SnikrFlow JNI name demangling.

JNI export names encode the Java package/class/method as:
    Java_<package>_<Class>_<method>
with underscores in the original identifier escaped as "_1", and an
optional "__<signature>" suffix for overload resolution.

This is a PRACTICAL HEURISTIC, not a complete JNI demangler. It doesn't
handle every escape sequence (unicode identifiers, "_00024" for '$', etc).
Results should be treated as "likely" class/method names, not ground
truth -- callers must not present this as guaranteed-correct.
"""

from __future__ import annotations

from typing import Optional

_ESCAPED_UNDERSCORE_MARKER = "\x00ESC_USCORE\x00"


def demangle_jni_name(name: str) -> tuple[Optional[str], Optional[str]]:
    """
    Best-effort extraction of (likely_java_class, likely_java_method)
    from a mangled JNI export name. Returns (None, None) if the name
    doesn't look like a standard JNI export.
    """
    if not name or not name.startswith("Java_"):
        return None, None

    remainder = name[len("Java_"):]
    if not remainder:
        return None, None

    # Overloaded native methods append "__<encoded signature>" -- strip it,
    # we only care about the class/method portion.
    if "__" in remainder:
        remainder = remainder.split("__", 1)[0]

    # JNI escapes a literal underscore in an identifier as "_1". Protect
    # those before splitting on plain "_" (which separates package/class/
    # method segments), then restore them afterward.
    remainder = remainder.replace("_1", _ESCAPED_UNDERSCORE_MARKER)
    parts = remainder.split("_")
    parts = [p.replace(_ESCAPED_UNDERSCORE_MARKER, "_") for p in parts]
    parts = [p for p in parts if p]  # drop empty segments

    if len(parts) < 2:
        return None, None

    method = parts[-1]
    java_class = ".".join(parts[:-1])

    return (java_class or None), (method or None)