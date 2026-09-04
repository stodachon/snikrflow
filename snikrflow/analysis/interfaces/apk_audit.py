"""
SnikrFlow APK audit orchestration.

Extracts the selected native librar(ies) from an APK to a temp directory
and runs the SAME `run_audit` pipeline used for standalone .so files on
each one -- no analysis logic is duplicated here, just file handling and
aggregation.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Optional

from snikrflow.analysis.interfaces.audit import run_audit
from snikrflow.android.apk import (
    extract_native_library,
    list_native_libraries,
    select_preferred_abi,
)
from snikrflow.core.exceptions import BinaryLoadError
from snikrflow.core.models import ApkAuditResult, ApkLibraryAudit
from snikrflow.elf.loader import load_binary


def audit_apk(
    apk_path: Path,
    abi: Optional[str] = None,
    all_abis: bool = False,
    deep_timeout_seconds: int = 30,
    save_libs_to: Optional[Path] = None,
) -> ApkAuditResult:
    entries = list_native_libraries(apk_path)
    available_abis = sorted({e.abi for e in entries})

    if not entries:
        return ApkAuditResult(apk_path=apk_path, available_abis=[], analyzed=[])

    if all_abis:
        selected_entries = entries
    elif abi:
        selected_entries = [e for e in entries if e.abi == abi]
        if not selected_entries:
            raise BinaryLoadError(
                f"No native libraries found for ABI '{abi}'. "
                f"Available ABIs: {', '.join(available_abis)}"
            )
    else:
        preferred = select_preferred_abi(entries)
        selected_entries = [e for e in entries if e.abi == preferred]

    analyzed: list[ApkLibraryAudit] = []

    with tempfile.TemporaryDirectory(prefix="snikrflow_apk_") as tmpdir:
        tmp_path = Path(tmpdir)
        for entry in selected_entries:
            library_name = entry.internal_path.rsplit("/", 1)[-1]
            try:
                extracted_path = extract_native_library(apk_path, entry, tmp_path)
                loaded = load_binary(extracted_path)
                audit_result = run_audit(loaded, deep_timeout_seconds=deep_timeout_seconds)

                persisted_path = None
                if save_libs_to is not None:
                    try:
                        dest_dir = save_libs_to / entry.abi
                        dest_dir.mkdir(parents=True, exist_ok=True)
                        dest_path = dest_dir / library_name
                        shutil.copy2(extracted_path, dest_path)
                        persisted_path = dest_path
                    except Exception:
                        # Saving is best-effort -- don't let a save failure
                        # discard an already-completed analysis.
                        persisted_path = None

                analyzed.append(
                    ApkLibraryAudit(
                        abi=entry.abi,
                        internal_path=entry.internal_path,
                        library_name=library_name,
                        audit=audit_result,
                        extracted_path=persisted_path,
                    )
                )
            except Exception as e:
                analyzed.append(
                    ApkLibraryAudit(
                        abi=entry.abi,
                        internal_path=entry.internal_path,
                        library_name=library_name,
                        error=str(e),
                    )
                )

    return ApkAuditResult(apk_path=apk_path, available_abis=available_abis, analyzed=analyzed)