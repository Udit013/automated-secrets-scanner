"""
SARIF 2.1.0 export.

Produces output compatible with GitHub Advanced Security code-scanning
upload (the same format used by CodeQL). Each secret type becomes a rule;
each finding becomes a result with a physical location and a fingerprint.
"""

_TOOL_NAME = "Automated Secrets Scanner"
_TOOL_VERSION = "2.0.0"
_INFO_URI = "https://github.com/Udit013/automated-secrets-scanner"

# SARIF result levels
_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

# GitHub security-severity score (0.0-10.0) for the Security tab.
_SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.0",
    "LOW": "2.5",
}


def _rule_id(secret_type: str) -> str:
    return "secret/" + secret_type.lower().replace(" ", "-")


def build_sarif(scan, findings: list) -> dict:
    # One rule per distinct secret type present in this scan.
    rules_by_type: dict[str, dict] = {}
    for f in findings:
        if f.secret_type in rules_by_type:
            continue
        rules_by_type[f.secret_type] = {
            "id": _rule_id(f.secret_type),
            "name": f.secret_type.replace(" ", ""),
            "shortDescription": {"text": f"Hardcoded {f.secret_type}"},
            "fullDescription": {
                "text": f"A {f.secret_type} was detected in source code. "
                        "Hardcoded secrets can lead to credential compromise."
            },
            "helpUri": _INFO_URI,
            "help": {"text": (f.remediation or "Rotate the credential and move it "
                              "to an environment variable.")},
            "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
            "properties": {
                "tags": ["security", "secrets"],
                "security-severity": _SECURITY_SEVERITY.get(f.severity, "5.0"),
            },
        }

    results = []
    for f in findings:
        results.append({
            "ruleId": _rule_id(f.secret_type),
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {
                "text": f"{f.secret_type} detected (risk score {f.risk_score}/100, "
                        f"entropy {f.entropy})."
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": max(f.line_number, 1)},
                }
            }],
            "partialFingerprints": {
                "secretsScanner/v1": f"{f.file_path}:{f.secret_type}:{f.matched_string}",
            },
            "properties": {
                "severity": f.severity,
                "riskScore": f.risk_score,
                "inGitHistory": f.is_in_history,
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "version": _TOOL_VERSION,
                    "informationUri": _INFO_URI,
                    "rules": list(rules_by_type.values()),
                }
            },
            "results": results,
            "properties": {
                "scanId": scan.id,
                "source": scan.source_ref,
            },
        }],
    }
