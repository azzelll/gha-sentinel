"""Output formats: human text, JSON and SARIF 2.1.0 (for GitHub code scanning)."""

from __future__ import annotations

import json

from .rules import SEVERITY_ORDER, Finding

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    lines = []
    for f in findings:
        where = f"{f.file}:{f.line} [{f.job}{' / ' + f.step if f.step else ''}]"
        lines.append(
            f"{f.severity.upper():8} {f.rule:22} {where}  (confidence: {f.confidence})"
        )
        lines.append(f"         {f.message}")
        lines.append(f"         evidence: {f.evidence}")
        lines.append(f"         fix: {f.remediation}")
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    lines.append(", ".join(f"{n} {s}" for s, n in counts.items() if n))
    return "\n".join(lines)


def as_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def sarif(findings: list[Finding]) -> str:
    rules = sorted({f.rule for f in findings})
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "gha-sentinel",
                            "informationUri": "https://github.com/azzelll/gha-sentinel",
                            "rules": [{"id": r, "name": r} for r in rules],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.rule,
                            "level": _SARIF_LEVEL[f.severity],
                            "message": {"text": f"{f.message} Fix: {f.remediation}"},
                            "properties": {
                                "severity": f.severity,
                                "confidence": f.confidence,
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.file},
                                        "region": {"startLine": max(f.line, 1)},
                                    }
                                }
                            ],
                        }
                        for f in findings
                    ],
                }
            ],
        },
        indent=2,
    )
