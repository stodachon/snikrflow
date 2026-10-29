"""The audit pipeline end to end, including APK input."""

import zipfile

import pytest

from snikrflow.analysis.interfaces.apk_audit import audit_apk
from snikrflow.analysis.interfaces.audit import run_audit
from snikrflow.core.exceptions import BinaryLoadError
from snikrflow.core.models import DataFlowStatus, ReachabilityType, RiskLevel


def test_audit_ranks_a_jni_to_memory_sink_path(target3):
    result = run_audit(target3, deep_timeout_seconds=60)

    assert (result.jni_count, result.sink_count) == (1, 1)
    assert result.interesting_path_count == 1
    assert result.symbolic_analysis_count == 1

    [finding] = result.findings
    assert finding.source_name == "Java_com_example_Native_parse"
    assert finding.sink_name == "strncpy"
    assert finding.sink_category == "memory"
    assert finding.reachability_type == ReachabilityType.STATICALLY_REACHABLE
    assert finding.data_flow_status == DataFlowStatus.POSSIBLE
    assert finding.risk_level == RiskLevel.HIGH       # reachable + possible data flow, memory (severity 2)


def test_audit_without_jni_entry_points_reports_no_findings(target1):
    result = run_audit(target1, deep_timeout_seconds=30)
    assert result.jni_count == 0
    assert result.findings == []


def test_audit_survives_a_stripped_binary(stripped):
    result = run_audit(stripped, deep_timeout_seconds=30)
    assert result.function_count > 0
    assert result.binary_info.is_stripped


# --- APK input ------------------------------------------------------------

@pytest.fixture
def apk_with_jni_lib(tmp_path, fixtures_dir):
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", b"dex")
        zf.write(fixtures_dir / "test_target3", "lib/x86_64/libjni.so")
    return path


def test_apk_audit_extracts_and_audits_the_native_library(apk_with_jni_lib):
    result = audit_apk(apk_with_jni_lib, deep_timeout_seconds=60)
    assert result.available_abis == ["x86_64"]
    [lib] = result.analyzed
    assert (lib.abi, lib.library_name, lib.error) == ("x86_64", "libjni.so", None)
    assert lib.audit.findings[0].sink_name == "strncpy"
    assert lib.extracted_path is None            # nothing saved unless asked


def test_apk_audit_can_keep_the_extracted_library(apk_with_jni_lib, tmp_path):
    out = tmp_path / "kept"
    result = audit_apk(apk_with_jni_lib, deep_timeout_seconds=30, save_libs_to=out)
    saved = result.analyzed[0].extracted_path
    assert saved == out / "x86_64" / "libjni.so"
    assert saved.exists() and saved.read_bytes()[:4] == b"\x7fELF"


def test_apk_audit_covers_every_abi_on_request(tmp_path, fixtures_dir):
    path = tmp_path / "multi.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.write(fixtures_dir / "test_target3", "lib/x86_64/libjni.so")
        zf.write(fixtures_dir / "test_target3", "lib/x86/libjni.so")
    default = audit_apk(path, deep_timeout_seconds=30)
    everything = audit_apk(path, all_abis=True, deep_timeout_seconds=30)
    assert [lib.abi for lib in default.analyzed] == ["x86_64"]     # preferred ABI only
    assert sorted(lib.abi for lib in everything.analyzed) == ["x86", "x86_64"]


def test_apk_audit_unknown_abi_lists_what_is_available(apk_with_jni_lib):
    with pytest.raises(BinaryLoadError, match="x86_64"):
        audit_apk(apk_with_jni_lib, abi="arm64-v8a")


def test_apk_without_native_code_is_not_an_error(tmp_path):
    path = tmp_path / "java_only.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", b"dex")
    result = audit_apk(path)
    assert result.available_abis == [] and result.analyzed == []


def test_a_library_that_cannot_be_analysed_is_reported_not_raised(tmp_path):
    path = tmp_path / "broken.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("lib/arm64-v8a/libbroken.so", b"definitely not an ELF" * 4)
    result = audit_apk(path)
    [lib] = result.analyzed
    assert lib.audit is None and lib.error        # the failure is recorded; the run continues
