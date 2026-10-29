"""Binary loading and ELF metadata (elf/loader.py, elf/metadata.py)."""

import pytest

from snikrflow.core.exceptions import BinaryLoadError
from snikrflow.core.models import Architecture, Endianness
from snikrflow.elf.loader import load_binary
from snikrflow.elf.metadata import extract_binary_info


def test_loads_fixture_with_expected_arch(target1):
    assert target1.architecture == Architecture.X86_64
    assert target1.endianness == Endianness.LITTLE
    assert target1.bitness == 64


def test_missing_file_is_a_clean_error(tmp_path):
    with pytest.raises(BinaryLoadError, match="not found"):
        load_binary(tmp_path / "nope.so")


def test_directory_is_a_clean_error(tmp_path):
    with pytest.raises(BinaryLoadError):
        load_binary(tmp_path)


def test_garbage_file_is_a_clean_error_not_a_traceback(tmp_path):
    junk = tmp_path / "junk.so"
    junk.write_bytes(b"this is definitely not an ELF file" * 8)
    with pytest.raises(BinaryLoadError):
        load_binary(junk)


def test_info_for_regular_executable(target1):
    info = extract_binary_info(target1)
    assert info.elf_type == "ET_EXEC"
    assert not info.is_shared_object
    assert not info.is_stripped
    assert info.function_count > 0
    assert info.section_count > 0 and info.segment_count > 0
    assert info.jni_candidate_count == 0


def test_info_counts_jni_candidates(target3):
    assert extract_binary_info(target3).jni_candidate_count == 1


def test_info_detects_stripped_binary(stripped):
    assert extract_binary_info(stripped).is_stripped
