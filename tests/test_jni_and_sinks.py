"""JNI discovery and sink detection."""

import pytest

from snikrflow.analysis.interfaces.jni import find_jni_functions
from snikrflow.analysis.interfaces.sinks import find_sinks
from snikrflow.sinks import database

from conftest import addr_of


def test_jni_export_is_found_and_demangled(target3):
    jni = find_jni_functions(target3)
    assert [f.name for f in jni] == ["Java_com_example_Native_parse"]
    f = jni[0]
    assert f.likely_java_class == "com.example.Native"
    assert f.likely_java_method == "parse"
    assert f.callers == [addr_of(target3, "main")]
    assert f.callees == [addr_of(target3, "copy_it")]


def test_binary_without_jni_exports_finds_none(target1):
    assert find_jni_functions(target1) == []


def test_wrapper_around_dangerous_sink_is_attributed_to_the_wrapper(target3):
    sinks = find_sinks(target3)
    assert [s.name for s in sinks] == ["strncpy"]
    sink = sinks[0]
    assert sink.category == "memory"
    assert sink.caller_count == 1
    assert sink.call_sites[0].caller_name == "copy_it"   # not the JNI export: it calls copy_it
    assert sink.total_call_site_count == 1


def test_call_site_address_lies_inside_the_caller(target3):
    sink = find_sinks(target3)[0]
    cs = sink.call_sites[0]
    assert cs.caller_address <= cs.call_site_addresses[0] < cs.caller_address + 0x100


def test_functions_that_are_not_sinks_are_not_reported(target1, target2):
    assert find_sinks(target1) == []
    assert find_sinks(target2) == []   # strlen is called, but isn't in the database


def test_sink_database_changes_flow_through_to_detection(target2, monkeypatch):
    monkeypatch.setitem(database._NAME_TO_CATEGORY, "strlen", "custom")
    sinks = find_sinks(target2)
    assert [(s.name, s.category) for s in sinks] == [("strlen", "custom")]
    assert sinks[0].call_sites[0].caller_name == "relay"
