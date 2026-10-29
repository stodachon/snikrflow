"""APK inspection (android/apk.py) -- pure ZIP handling, no analysis."""

import zipfile
from pathlib import Path

import pytest

from snikrflow.android.apk import (
    extract_native_library,
    is_apk,
    list_native_libraries,
    select_preferred_abi,
)
from snikrflow.core.exceptions import BinaryLoadError


def make_apk(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


@pytest.fixture
def apk(tmp_path):
    return make_apk(
        tmp_path / "app.apk",
        {
            "AndroidManifest.xml": b"<manifest/>",
            "classes.dex": b"dex",
            "lib/arm64-v8a/libfoo.so": b"arm64-foo",
            "lib/x86_64/libfoo.so": b"x86_64-foo",
            "lib/armeabi-v7a/libbar.so": b"arm-bar",
            "lib/arm64-v8a/not_a_library.txt": b"nope",   # wrong extension
            "lib/x86/nested/deep.so": b"too deep",        # wrong depth
        },
    )


def test_is_apk_by_extension_and_by_zip_magic(tmp_path, apk):
    assert is_apk(apk)
    zip_without_apk_ext = make_apk(tmp_path / "bundle.bin", {"a.txt": b"x"})
    assert is_apk(zip_without_apk_ext)


def test_is_apk_rejects_non_zip_and_missing(tmp_path):
    plain = tmp_path / "libfoo.so"
    plain.write_bytes(b"\x7fELF not a zip")
    assert not is_apk(plain)
    assert not is_apk(tmp_path / "does_not_exist.bin")


def test_lists_only_real_native_libraries(apk):
    entries = list_native_libraries(apk)
    assert {(e.abi, e.internal_path) for e in entries} == {
        ("arm64-v8a", "lib/arm64-v8a/libfoo.so"),
        ("x86_64", "lib/x86_64/libfoo.so"),
        ("armeabi-v7a", "lib/armeabi-v7a/libbar.so"),
    }


def test_apk_without_native_libs_lists_nothing(tmp_path):
    assert list_native_libraries(make_apk(tmp_path / "pure_java.apk", {"classes.dex": b"x"})) == []


def test_preferred_abi_follows_device_preference_order(apk, tmp_path):
    assert select_preferred_abi(list_native_libraries(apk)) == "arm64-v8a"

    x86_only = make_apk(
        tmp_path / "x86.apk",
        {"lib/x86/liba.so": b"a", "lib/x86_64/liba.so": b"a"},
    )
    assert select_preferred_abi(list_native_libraries(x86_only)) == "x86_64"

    assert select_preferred_abi([]) is None


def test_unknown_abi_is_still_selectable(tmp_path):
    odd = make_apk(tmp_path / "odd.apk", {"lib/riscv64/liba.so": b"a"})
    assert select_preferred_abi(list_native_libraries(odd)) == "riscv64"


def test_extract_native_library_writes_the_right_bytes(apk, tmp_path):
    entry = next(e for e in list_native_libraries(apk) if e.abi == "x86_64")
    out = extract_native_library(apk, entry, tmp_path / "out")
    assert out.read_bytes() == b"x86_64-foo"


def test_missing_or_corrupt_apk_raises_load_error(tmp_path):
    with pytest.raises(BinaryLoadError):
        list_native_libraries(tmp_path / "nope.apk")

    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"this is not a zip file")
    with pytest.raises(BinaryLoadError):
        list_native_libraries(bad)
