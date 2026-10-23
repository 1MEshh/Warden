"""
OASIS SARIF v2.1.0 Formatter for GitHub Advanced Security & SIEM Ingestion.

Converts normalized findings from `signatures.py`, `supply_chain.py`, and
`ast_auditor.py` into a valid SARIF v2.1.0 JSON report with CWE taxonomy
tags and exact physical file locations.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List

from vault_warden import __version__

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"

SEVERITY_TO_SARIF_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

SEVERITY_TO_SECURITY_SCORE: Dict[str, str] = {
    "critical": "9.5",
    "high": "7.8",
    "medium": "5.5",
    "low": "3.0",
}


def build_sarif_report(findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a SARIF v2.1.0 dictionary from normalized finding dictionaries.
    """
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for item in findings:
        rule_id = str(item.get("rule_id", "VW-GEN-000"))
        rule_name = str(item.get("rule_name", "Security Finding"))
        cwe_id = str(item.get("cwe_id", "CWE-798"))
        severity = str(item.get("severity", "medium")).lower()
        file_path = str(item.get("file_path", "unknown"))
        line_number = max(1, int(item.get("line_number", 1)))
        column = max(1, int(item.get("column", 1)))
        description = str(item.get("description", rule_name))

        sarif_level = SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")
        security_score = SEVERITY_TO_SECURITY_SCORE.get(severity, "5.5")

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_name.replace(" ", ""),
                "shortDescription": {"text": rule_name},
                "fullDescription": {"text": f"{rule_name} ({cwe_id})"},
                "defaultConfiguration": {"level": sarif_level},
                "properties": {
                    "tags": ["security", f"external/cwe/{cwe_id.lower()}"],
                    "security-severity": security_score,
                    "precision": "high",
                },
            }

        result_entry: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line_number,
                            "startColumn": column,
                        },
                    }
                }
            ],
            "properties": {
                "cwe": cwe_id,
                "severity": severity,
                "category": item.get("category", "security"),
            },
        }

        if item.get("masked_secret"):
            result_entry["properties"]["masked_secret"] = item["masked_secret"]
        if item.get("commit_hash"):
            result_entry["properties"]["commit_hash"] = item["commit_hash"]

        results.append(result_entry)

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vault-warden-ir",
                        "version": __version__,
                        "informationUri": "https://github.com/1MEshh/Warden",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def format_sarif_json(findings: Iterable[Dict[str, Any]], indent: int = 2) -> str:
    """Serialize findings into a formatted SARIF v2.1.0 JSON string."""
    return json.dumps(build_sarif_report(findings), indent=indent)
