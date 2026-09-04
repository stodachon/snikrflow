"""
SnikrFlow APK support.

An APK is just a ZIP file. Native libraries live under lib/<abi>/*.so --
often the same library built for multiple architectures. This module
ONLY handles locating and extracting those .so files; the actual
analysis is the same ELF pipeline used everywhere else in SnikrFlow,
just run once per extracted library (see analysis/interfaces/apk_audit.py).
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from snikrflow.core.exceptions import BinaryLoadError

# Preference order when auto-selecting a single ABI to analyze -- closest
# to what a real modern ARM64 Android device would actually load.
_ABI_PREFERENCE = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86", "armeabi")


@dataclass
class NativeLibraryEntry:
    abi: str
    internal_path: str  # e.g. "lib/arm64-v8a/libfoo.so"
    size: int


def is_apk(path: Path) -> bool:
    """True if this looks like an APK (by extension, or by being a valid ZIP)."""
    if path.suffix.lower() == ".apk":
        return True
    try:
        return path.is_file() and zipfile.is_zipfile(path)
    except Exception:
        return False


def list_native_libraries(apk_path: Path) -> list[NativeLibraryEntry]:
    if not apk_path.exists():
        raise BinaryLoadError(f"File not found: {apk_path}")

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            entries = []
            for info in zf.infolist():
                parts = info.filename.split("/")
                if len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so"):
                    entries.append(
                        NativeLibraryEntry(
                            abi=parts[1],
                            internal_path=info.filename,
                            size=info.file_size,
                        )
                    )
            return entries
    except zipfile.BadZipFile as e:
        raise BinaryLoadError(f"'{apk_path.name}' is not a valid APK/ZIP file: {e}") from e


def select_preferred_abi(entries: list[NativeLibraryEntry]) -> Optional[str]:
    available = {e.abi for e in entries}
    for preferred in _ABI_PREFERENCE:
        if preferred in available:
            return preferred
    return sorted(available)[0] if available else None


def extract_native_library(apk_path: Path, entry: NativeLibraryEntry, extract_dir: Path) -> Path:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            extracted = zf.extract(entry.internal_path, path=extract_dir)
            return Path(extracted)
    except (zipfile.BadZipFile, KeyError) as e:
        raise BinaryLoadError(f"Failed to extract '{entry.internal_path}' from APK: {e}") from e