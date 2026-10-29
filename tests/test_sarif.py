"""SARIF 2.1.0 export (reporting/sarif.py)."""

import json
from pathlib import Path

import pytest

from snikrflow.core.models import (
    AnalysisFinding,
    Architecture,
    AuditResult,
    BinaryInfo,
    Confidence,
    DataFlowStatus,
    Endianness,
    ReachabilityType,
    RiskLevel,
)
from snikrflow.reporting.sarif import build_sarif_document, write_sarif


def make_result(*findings: AnalysisFinding) -> AuditResult:
    info = BinaryInfo(
        path=Path("libfoo.so"),
        architecture=Architecture.ARM64,
        endianness=Endianness.LITTLE,
        bitness=64,
        elf_type="ET_DYN",
        entry_point=0,
        is_shared_object=True,
        is_stripped=False,
    )
    return AuditResult(
        binary_info=info,
        function_count=10,
        jni_count=1,
        sink_count=len(findings),
        interesting_path_count=len(findings),
        symbolic_analysis_count=len(findings),
        findings=list(findings),
    )


def make_finding(risk=RiskLevel.MEDIUM, category="memory", sink="strncpy") -> AnalysisFinding:
    return AnalysisFinding(
        title=f"JNI -> {category}",
        source_address=0x403A00,
        source_name="Java_com_example_Native_parse",
        sink_address=0x400D80,
        sink_name=sink,
        sink_category=category,
        reachability_type=ReachabilityType.STATICALLY_REACHABLE,
        data_flow_status=DataFlowStatus.POSSIBLE,
        risk_level=risk,
        confidence=Confidence.MEDIUM,
        notes=["a note"],
    )


def test_document_has_sarif_2_1_0_shape():
    doc = build_sarif_document([(make_result(make_finding()), Path("libfoo.so"))])
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "SnikrFlow"
    assert run["tool"]["driver"]["version"]
    assert len(run["results"]) == 1


@pytest.mark.parametrize(
    "risk, level",
    [
        (RiskLevel.CRITICAL, "error"),
        (RiskLevel.HIGH, "error"),
        (RiskLevel.MEDIUM, "warning"),
        (RiskLevel.LOW, "note"),
    ],
)
def test_risk_maps_to_sarif_level(risk, level):
    doc = build_sarif_document([(make_result(make_finding(risk=risk)), Path("libfoo.so"))])
    assert doc["runs"][0]["results"][0]["level"] == level


def test_result_carries_addresses_and_properties():
    doc = build_sarif_document([(make_result(make_finding()), Path("libfoo.so"))])
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "snikrflow/memory"
    assert result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "0x400d80"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "libfoo.so"
    props = result["properties"]
    assert props["sourceAddress"] == "0x403a00"
    assert props["dataFlowStatus"] == "possible"
    assert props["riskLevel"] == "medium"


def test_rules_are_deduplicated_across_findings_and_libraries():
    a = make_result(make_finding(category="memory"), make_finding(category="memory"))
    b = make_result(make_finding(category="comparison", sink="strncmp"))
    doc = build_sarif_document([(a, Path("lib/arm64-v8a/liba.so")), (b, Path("lib/x86_64/libb.so"))])
    run = doc["runs"][0]
    assert len(run["results"]) == 3
    assert sorted(r["id"] for r in run["tool"]["driver"]["rules"]) == [
        "snikrflow/comparison",
        "snikrflow/memory",
    ]
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]}
    assert uris == {"lib/arm64-v8a/liba.so", "lib/x86_64/libb.so"}


def test_no_findings_still_produces_a_valid_empty_run():
    doc = build_sarif_document([(make_result(), Path("libfoo.so"))])
    assert doc["runs"][0]["results"] == []


def test_write_sarif_writes_parseable_json(tmp_path):
    out = tmp_path / "findings.sarif"
    write_sarif([(make_result(make_finding()), Path("libfoo.so"))], out)
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"
