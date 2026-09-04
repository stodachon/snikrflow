"""
SnikrFlow SARIF export.

Produces a SARIF 2.1.0 document from one or more AuditResults, for
consumption by CI pipelines, GitHub code scanning, and other SARIF-aware
tooling. This is an EXPORT FORMAT ONLY -- it doesn't change what
SnikrFlow finds, just how the same findings get serialized. Supports
multiple (result, binary_label) entries so a single SARIF file can cover
every native library analyzed from one APK.
"""

from __future__ import annotations

import json
from pathlib import Path

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from snikrflow.core.models import AuditResult, RiskLevel

try:
    SNIKRFLOW_VERSION = _pkg_version("snikrflow")
except PackageNotFoundError:
    SNIKRFLOW_VERSION = "0.1.0-dev"
SNIKRFLOW_INFO_URI = "https://github.com/Stodachon/snikrflow"

_RISK_TO_SARIF_LEVEL = {
    RiskLevel.CRITICAL: "error",
    RiskLevel.HIGH: "error",
    RiskLevel.MEDIUM: "warning",
    RiskLevel.LOW: "note",
}


def build_sarif_document(entries: list[tuple[AuditResult, Path]]) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for result, binary_label in entries:
        for f in result.findings:
            rule_id = f"snikrflow/{f.sink_category}"

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f"{f.sink_category}_sink_reachable",
                    "shortDescription": {
                        "text": f"Reachable {f.sink_category} security-sensitive operation"
                    },
                    "fullDescription": {
                        "text": (
                            f"A JNI entry point has a statically-reachable call chain "
                            f"to a {f.sink_category}-category security-sensitive "
                            f"function. This is a prioritization signal, not a "
                            f"confirmed vulnerability -- manual verification required."
                        )
                    },
                }

            results.append(
                {
                    "ruleId": rule_id,
                    "level": _RISK_TO_SARIF_LEVEL.get(f.risk_level, "note"),
                    "message": {
                        "text": (
                            f"{f.source_name} ({hex(f.source_address)}) has a "
                            f"{f.reachability_type.value} path to {f.sink_name} "
                            f"({hex(f.sink_address)}), a {f.sink_category} sink. "
                            f"Risk: {f.risk_level.value}, confidence: {f.confidence.value}."
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": str(binary_label)}
                            },
                            "logicalLocations": [
                                {
                                    "name": f.sink_name,
                                    "fullyQualifiedName": hex(f.sink_address),
                                    "kind": "function",
                                }
                            ],
                        }
                    ],
                    "properties": {
                        "sourceAddress": hex(f.source_address),
                        "sourceName": f.source_name,
                        "sinkAddress": hex(f.sink_address),
                        "sinkCategory": f.sink_category,
                        "reachabilityType": f.reachability_type.value,
                        "dataFlowStatus": f.data_flow_status.value if f.data_flow_status else None,
                        "riskLevel": f.risk_level.value,
                        "confidence": f.confidence.value,
                        "notes": f.notes,
                    },
                }
            )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SnikrFlow",
                        "version": SNIKRFLOW_VERSION,
                        "informationUri": SNIKRFLOW_INFO_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(entries: list[tuple[AuditResult, Path]], output_path: Path) -> None:
    doc = build_sarif_document(entries)
    output_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")