"""
Shared test fixtures.

The tests run against small, deterministic ELF binaries committed under
tests/fixtures/ (sources sit next to them as .c files). They're prebuilt
so the suite runs identically on Windows, Linux and CI without needing a
C compiler. Functions are looked up BY NAME rather than hardcoded
addresses, so a rebuilt fixture won't silently break the tests.

Rebuild recipe (x86_64 Linux):
    gcc -O0 -fno-builtin -fno-stack-protector -no-pie -o test_target3 test_target3.c
"""

from pathlib import Path

import pytest

from snikrflow.analysis.interfaces.functions import find_functions
from snikrflow.elf.loader import load_binary

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def target1():
    """check_password() -> sink_reached() behind a 4-byte 'Snik' comparison."""
    return load_binary(FIXTURES / "test_target")


@pytest.fixture(scope="session")
def target2():
    """relay() passes its buffer pointer straight into strlen()."""
    return load_binary(FIXTURES / "test_target2")


@pytest.fixture(scope="session")
def target3():
    """Java_com_example_Native_parse -> copy_it -> strncpy (JNI-style export)."""
    return load_binary(FIXTURES / "test_target3")


@pytest.fixture(scope="session")
def target4():
    """explode(): 32 data-dependent branches (path explosion) before sink_reached()."""
    return load_binary(FIXTURES / "test_target4")


@pytest.fixture(scope="session")
def target5():
    """main -> run_callback(sink_reached): a call the call graph cannot resolve."""
    return load_binary(FIXTURES / "test_target5")


@pytest.fixture(scope="session")
def stripped():
    """Same program as target1 with its symbol table stripped."""
    return load_binary(FIXTURES / "test_target_stripped")


def addr_of(binary, name: str, plt: bool = False) -> int:
    """Address of the function called `name` (optionally the PLT stub)."""
    for f in find_functions(binary):
        if f.name == name and f.is_plt_stub == plt:
            return f.address
    raise AssertionError(f"function {name!r} (plt={plt}) not found in {binary.path.name}")
