"""Unit tests for the remediation patch generator."""

from types import SimpleNamespace

from app.scanner.remediation import (
    build_patch,
    build_remediation,
    env_var_name,
    suggest_replacement,
)


def _scan():
    return SimpleNamespace(id="scan-abcdef12", source_ref="https://github.com/acme/repo")


def _finding(**over):
    base = dict(
        secret_type="Stripe Live Secret Key",
        severity="CRITICAL",
        file_path="payment/stripe.py",
        line_number=12,
        context='stripe_key = "sk_live_MASKED"',
        remediation="Revoke in Stripe Dashboard.",
    )
    base.update(over)
    return SimpleNamespace(**base)


class TestEnvVarName:
    def test_prefers_original_identifier(self):
        assert env_var_name("Generic Secret", 'my_api_token = "x"') == "MY_API_TOKEN"

    def test_falls_back_to_type_mapping(self):
        assert env_var_name("AWS Access Key", "") == "AWS_ACCESS_KEY_ID"
        assert env_var_name("Database Connection String", "") == "DATABASE_URL"

    def test_unknown_type_gets_generic_name(self):
        assert env_var_name("Mystery Credential", "") == "SECRET_VALUE"


class TestSuggestReplacement:
    def test_python(self):
        out = suggest_replacement("app/config.py", 'api_key = "x"', "API_KEY")
        assert out == 'api_key = os.getenv("API_KEY")'

    def test_node(self):
        out = suggest_replacement("src/index.ts", 'apiKey = "x"', "API_KEY")
        assert out == "const apiKey = process.env.API_KEY"

    def test_go(self):
        out = suggest_replacement("main.go", 'apiKey = "x"', "API_KEY")
        assert out == 'apiKey := os.Getenv("API_KEY")'

    def test_env_file(self):
        out = suggest_replacement(".env.production", "API_KEY=x", "API_KEY")
        assert out == "API_KEY=${API_KEY}"

    def test_unknown_extension_gets_generic_guidance(self):
        out = suggest_replacement("config.xml", "", "API_KEY")
        assert "API_KEY" in out


class TestBuildRemediation:
    def test_report_shape(self):
        report = build_remediation(_scan(), [_finding()])
        assert report["total_findings"] == 1
        assert len(report["findings"]) == 1
        item = report["findings"][0]
        assert item["before"] == 'stripe_key = "sk_live_MASKED"'
        assert "os.getenv" in item["after"]
        assert len(report["next_steps"]) >= 4

    def test_env_example_deduplicates_vars(self):
        findings = [_finding(), _finding(line_number=50)]
        report = build_remediation(_scan(), findings)
        assert report["env_example"].count("STRIPE_KEY=") == 1


class TestBuildPatch:
    def test_patch_contains_diff_hunks(self):
        patch = build_patch(_scan(), [_finding()])
        assert "--- a/payment/stripe.py" in patch
        assert "+++ b/payment/stripe.py" in patch
        assert '-stripe_key = "sk_live_MASKED"' in patch
        assert '+stripe_key = os.getenv("STRIPE_KEY")' in patch

    def test_patch_groups_findings_by_file(self):
        findings = [
            _finding(line_number=30),
            _finding(line_number=10),
            _finding(file_path="other.py"),
        ]
        patch = build_patch(_scan(), findings)
        assert patch.count("--- a/payment/stripe.py") == 1
        assert patch.count("--- a/other.py") == 1
        # Hunks within a file sorted by line number
        assert patch.index("@@ line 10") < patch.index("@@ line 30")

    def test_patch_includes_env_example_and_next_steps(self):
        patch = build_patch(_scan(), [_finding()])
        assert "# ---- .env.example ----" in patch
        assert "# ---- Next steps ----" in patch
