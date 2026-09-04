"""
SnikrFlow ELF loader.

This module is the ONLY place in Milestone 1 that touches angr directly.
It wraps angr.Project loading and translates failures into SnikrFlow
exceptions. Everything above this layer (CLI, future audit engine) should
depend on `load_binary()` and get back a `LoadedBinary`, never a raw
angr.Project reference passed around casually.

Note: LoadedBinary.project *does* hold a real angr.Project internally,
because later backend modules (functions.py, cfg.py, symbolic.py) need
it. But CLI code and reporting code should never reach into .project
directly -- they go through the analysis interfaces instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from snikrflow.core.exceptions import BinaryLoadError, UnsupportedArchitectureError
from snikrflow.core.models import Architecture, Endianness

# Logging MUST be configured before `import angr` below. angr's package
# init triggers a submodule (state_plugins.unicorn_engine) that logs its
# "unicornlib.dll not found" message immediately at import time, so
# configuring the logger afterward is too late -- the message will
# already have been emitted by the time we get to it.
import logging

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

# angr import is confined to this module (and the rest of backends/angr/)
import angr


_ARCH_MAP = {
    "AMD64": Architecture.X86_64,
    "X86": Architecture.X86,
    "ARM": Architecture.ARM,
    "ARMEL": Architecture.ARM,
    "ARMHF": Architecture.ARM,
    "AARCH64": Architecture.ARM64,
    "MIPS32": Architecture.MIPS,
    "MIPS64": Architecture.MIPS64,
}


@dataclass
class LoadedBinary:
    """
    Internal handle SnikrFlow passes between backend modules. Holds the
    real angr.Project plus some cheap-to-compute facts we don't want to
    recompute every time.
    """
    path: Path
    project: "angr.Project"
    architecture: Architecture
    endianness: Endianness
    bitness: int


def load_binary(path: Path) -> LoadedBinary:
    """
    Load a binary via angr and return a SnikrFlow LoadedBinary.

    Raises:
        BinaryLoadError: file missing, malformed, or angr couldn't parse it.
        UnsupportedArchitectureError: architecture not in our support map.
    """
    if not path.exists():
        raise BinaryLoadError(f"File not found: {path}")

    if not path.is_file():
        raise BinaryLoadError(f"Not a file: {path}")

    try:
        project = angr.Project(str(path), auto_load_libs=False)
    except Exception as e:
        raise BinaryLoadError(f"angr could not load '{path.name}': {e}") from e

    arch_name = project.arch.name
    architecture = _ARCH_MAP.get(arch_name)
    if architecture is None:
        raise UnsupportedArchitectureError(
            f"Architecture '{arch_name}' is not yet supported by SnikrFlow."
        )

    endianness = (
        Endianness.LITTLE
        if project.arch.memory_endness == "Iend_LE"
        else Endianness.BIG
    )

    bitness = project.arch.bits

    return LoadedBinary(
        path=path,
        project=project,
        architecture=architecture,
        endianness=endianness,
        bitness=bitness,
    )