"""
SnikrFlow sink database -- lookup layer over the signature file.
"""

from __future__ import annotations

from typing import Optional

from snikrflow.sinks.signatures import SINK_SIGNATURES

_NAME_TO_CATEGORY: dict[str, str] = {
    name: category
    for category, names in SINK_SIGNATURES.items()
    for name in names
}


def lookup_category(function_name: str) -> Optional[str]:
    """Return the sink category for a function name, or None if not a known sink."""
    if not function_name:
        return None
    return _NAME_TO_CATEGORY.get(function_name)


def is_sink(function_name: str) -> bool:
    return lookup_category(function_name) is not None


def all_categories() -> list[str]:
    return list(SINK_SIGNATURES.keys())