"""Sink signature database: lookups, categories, and configurability."""

import pytest

from snikrflow.sinks import database
from snikrflow.sinks.database import all_categories, is_sink, lookup_category
from snikrflow.sinks.signatures import SINK_SIGNATURES


@pytest.mark.parametrize(
    "name, category",
    [
        ("memcpy", "memory"),
        ("strncpy", "memory"),
        ("snprintf", "memory"),
        ("system", "process_execution"),
        ("execve", "process_execution"),
        ("fopen", "filesystem"),
        ("unlink", "filesystem"),
        ("connect", "networking"),
        ("recvfrom", "networking"),
        ("dlopen", "dynamic_loading"),
        ("dlsym", "dynamic_loading"),
        ("strstr", "comparison"),
        ("strncmp", "comparison"),
        ("memcmp", "comparison"),
    ],
)
def test_known_sinks_resolve_to_their_category(name, category):
    assert lookup_category(name) == category
    assert is_sink(name)


@pytest.mark.parametrize("name", ["printf", "malloc", "strlen", "main", "", "MEMCPY"])
def test_non_sinks_return_none(name):
    assert lookup_category(name) is None
    assert not is_sink(name)


def test_all_categories_matches_signature_file():
    assert set(all_categories()) == set(SINK_SIGNATURES)
    for expected in ("memory", "process_execution", "filesystem",
                     "networking", "dynamic_loading", "comparison"):
        assert expected in all_categories()


def test_no_function_name_appears_in_two_categories():
    # The lookup table is name -> category, so a duplicate would silently
    # shadow one of the categories.
    seen = {}
    for category, names in SINK_SIGNATURES.items():
        for name in names:
            assert name not in seen, f"{name!r} is in both {seen[name]!r} and {category!r}"
            seen[name] = category


def test_database_is_configurable(monkeypatch):
    monkeypatch.setitem(database._NAME_TO_CATEGORY, "my_custom_sink", "custom")
    assert lookup_category("my_custom_sink") == "custom"
