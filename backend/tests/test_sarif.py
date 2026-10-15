"""Unit tests for SARIF 2.1.0 export."""

from types import SimpleNamespace

from app.scanner.sarif import build_sarif


def _scan():
    return SimpleNamespace(id="scan-123", source_ref="https://github.com/acme/repo")


def _finding(**over):
    base = dict(
        secret_type="AWS Access Key",
        severity="CRITICAL",
        file_path="config/aws.py",
        line_number=12,
        matched_string="AKIA***MASKED",
        entropy=4.2,
        risk_score=88,
        is_in_history=True,
        remediation="Revoke in IAM.",
    )
    base.update(over)
    return SimpleNamespace(**base)


class TestBuildSarif:
    def test_top_level_structure(self):
        doc = build_sarif(_scan(), [_finding()])
        assert doc["version"] == "2.1.0"
        assert "sarif-2.1.0" in doc["$schema"]
        assert len(doc["runs"]) == 1

    def test_one_rule_per_distinct_type(self):
        findings = [
            _finding(),
            _finding(line_number=99),  # same type — no extra rule
            _finding(secret_type="JWT Token", severity="HIGH"),
        ]
        run = build_sarif(_scan(), findings)["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) == 2
        assert len(run["results"]) == 3

    def test_rule_ids_are_slugified(self):
        run = build_sarif(_scan(), [_finding()])["runs"][0]
        assert run["tool"]["driver"]["rules"][0]["id"] == "secret/aws-access-key"
        assert run["results"][0]["ruleId"] == "secret/aws-access-key"

    def test_severity_level_mapping(self):
        cases = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        for sev, level in cases.items():
            run = build_sarif(_scan(), [_finding(severity=sev)])["runs"][0]
            assert run["results"][0]["level"] == level

    def test_result_location_and_fingerprint(self):
        result = build_sarif(_scan(), [_finding()])["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "config/aws.py"
        assert loc["region"]["startLine"] == 12
        assert "secretsScanner/v1" in result["partialFingerprints"]

    def test_line_number_floor_is_one(self):
        result = build_sarif(_scan(), [_finding(line_number=0)])["runs"][0]["results"][0]
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1

    def test_security_severity_property_present(self):
        rule = build_sarif(_scan(), [_finding()])["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "9.5"

    def test_empty_findings_produce_valid_empty_run(self):
        run = build_sarif(_scan(), [])["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []


def test_credential_fingerprint_is_a_partial_fingerprint():
    from app.scanner.core import scan_text
    f = scan_text('k = "AKIA' + 'V3WBCDEF4GHI7JKM"', "a.py")[0]
    result = build_sarif(SimpleNamespace(id="s", source_ref="r"), [f])["runs"][0]["results"][0]
    assert result["partialFingerprints"]["cipherwatch/credential/v1"] == f.fingerprint
