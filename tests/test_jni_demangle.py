"""Heuristic JNI name demangling (elf/jni.py)."""

import pytest

from snikrflow.elf.jni import demangle_jni_name


@pytest.mark.parametrize(
    "name, expected",
    [
        ("Java_com_example_Native_parse", ("com.example.Native", "parse")),
        (
            "Java_sg_vantagepoint_uncrackable3_MainActivity_init",
            ("sg.vantagepoint.uncrackable3.MainActivity", "init"),
        ),
        # "_1" is the JNI escape for a literal underscore in an identifier
        ("Java_com_my_1app_Native_run", ("com.my_app.Native", "run")),
        # "__<signature>" suffix marks an overloaded native method
        (
            "Java_com_example_Foo_bar__Ljava_lang_String_2",
            ("com.example.Foo", "bar"),
        ),
    ],
)
def test_demangles_standard_jni_exports(name, expected):
    assert demangle_jni_name(name) == expected


@pytest.mark.parametrize(
    "name",
    ["", "memcpy", "JNI_OnLoad", "Java_", "Java_onlyonepart", "java_lowercase_prefix"],
)
def test_non_jni_or_unparseable_names_return_none(name):
    assert demangle_jni_name(name) == (None, None)
