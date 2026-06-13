import re
from dataclasses import dataclass
from typing import List


@dataclass
class SecretPattern:
    name: str
    regex: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    format_specific: bool  # bypass entropy check
    remediation: str


PATTERNS: List[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key",
        regex=r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
        severity="CRITICAL",
        format_specific=True,
        remediation=(
            "1. Immediately revoke this key in AWS IAM Console.\n"
            "2. Rotate: create a new key, update all services, then delete the exposed key.\n"
            "3. Store in AWS Secrets Manager or environment variables.\n"
            "4. Add .env to .gitignore and use python-dotenv."
        ),
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        regex=r'(?i)aws[_\-\s]*(secret|secret_access)[_\-\s]*key[\s]*[=:]+[\s]*["\']?([A-Za-z0-9/+]{40})["\']?',
        severity="CRITICAL",
        format_specific=True,
        remediation=(
            "1. Immediately revoke this AWS secret key in IAM Console.\n"
            "2. Rotate the associated access key pair.\n"
            "3. Use IAM roles instead of long-lived credentials."
        ),
    ),
    SecretPattern(
        name="GitHub Personal Access Token",
        regex=r"ghp_[0-9a-zA-Z]{36}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke the token at github.com/settings/tokens.\n"
            "2. Use fine-grained tokens with minimal scopes.\n"
            "3. Store in environment variables or GitHub Actions secrets."
        ),
    ),
    SecretPattern(
        name="GitHub OAuth Token",
        regex=r"gho_[0-9a-zA-Z]{36}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke the OAuth token via GitHub API or settings.\n"
            "2. Never hardcode OAuth tokens — use environment variables."
        ),
    ),
    SecretPattern(
        name="GitHub App Token",
        regex=r"(ghu|ghs|ghr)_[0-9a-zA-Z]{36}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke via GitHub App settings.\n"
            "2. Store app credentials in environment variables."
        ),
    ),
    SecretPattern(
        name="Google API Key",
        regex=r"AIza[0-9A-Za-z\-_]{35}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke the key in Google Cloud Console → APIs & Services → Credentials.\n"
            "2. Create a new restricted key with only required APIs enabled.\n"
            "3. Store in environment variables or GCP Secret Manager."
        ),
    ),
    SecretPattern(
        name="GCP Service Account Key",
        regex=r'"type":\s*"service_account"',
        severity="CRITICAL",
        format_specific=True,
        remediation=(
            "1. Delete the service account key in GCP IAM Console immediately.\n"
            "2. Rotate by creating a new key.\n"
            "3. Use Workload Identity Federation instead of key files in production."
        ),
    ),
    SecretPattern(
        name="Stripe Live Secret Key",
        regex=r"sk_live_[0-9a-zA-Z]{24}",
        severity="CRITICAL",
        format_specific=True,
        remediation=(
            "1. Immediately roll the key in Stripe Dashboard → Developers → API keys.\n"
            "2. Monitor for unauthorized charges.\n"
            "3. Use Stripe's restricted keys with minimum permissions."
        ),
    ),
    SecretPattern(
        name="Stripe Test Secret Key",
        regex=r"sk_test_[0-9a-zA-Z]{24}",
        severity="MEDIUM",
        format_specific=True,
        remediation=(
            "1. Roll the test key in Stripe Dashboard.\n"
            "2. Store in environment variables — test keys should still be treated as secrets."
        ),
    ),
    SecretPattern(
        name="Slack Bot Token",
        regex=r"xoxb-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke the token at api.slack.com/apps → OAuth & Permissions.\n"
            "2. Rotate and store in environment variables."
        ),
    ),
    SecretPattern(
        name="Slack App Token",
        regex=r"xapp-[0-9]-[A-Z0-9]{10,12}-[0-9]{13}-[0-9a-f]{64}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke at api.slack.com/apps.\n"
            "2. Store in environment variables."
        ),
    ),
    SecretPattern(
        name="Twilio API Key",
        regex=r"SK[0-9a-fA-F]{32}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke the API key in Twilio Console → Account → API Keys.\n"
            "2. Store in environment variables."
        ),
    ),
    SecretPattern(
        name="SendGrid API Key",
        regex=r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke the key at app.sendgrid.com → Settings → API Keys.\n"
            "2. Create a new key with minimum required permissions."
        ),
    ),
    SecretPattern(
        name="Private SSH Key",
        regex=r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        severity="CRITICAL",
        format_specific=True,
        remediation=(
            "1. Revoke the key immediately from all authorized_keys files.\n"
            "2. Generate a new key pair: ssh-keygen -t ed25519.\n"
            "3. Private keys must NEVER be committed — add to .gitignore."
        ),
    ),
    SecretPattern(
        name="PGP Private Key",
        regex=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity="CRITICAL",
        format_specific=True,
        remediation=(
            "1. Revoke the PGP key and publish a revocation certificate.\n"
            "2. Generate a new key pair and update all trusted parties."
        ),
    ),
    SecretPattern(
        name="JWT Token",
        regex=r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]{10,}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Invalidate the token by rotating the signing secret.\n"
            "2. Never hardcode JWT tokens — they should be generated at runtime.\n"
            "3. Use short expiry times and refresh token rotation."
        ),
    ),
    SecretPattern(
        name="Database Connection String",
        regex=r"(mongodb(\+srv)?|mysql|postgres(ql)?|redis|mssql|oracle)://[^:\s]+:[^@\s]+@[^\s\"'`]+",
        severity="CRITICAL",
        format_specific=True,
        remediation=(
            "1. Rotate the database password immediately.\n"
            "2. Store the connection string in environment variables.\n"
            "3. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault).\n"
            "4. Restrict DB network access with firewall rules."
        ),
    ),
    SecretPattern(
        name="Generic API Key",
        regex=r'(?i)(api[_\-\s]?key|apikey|api[_\-\s]?secret)["\s]*[=:]+[\s"\']*([0-9a-zA-Z\-_]{32,64})["\']?',
        severity="HIGH",
        format_specific=False,
        remediation=(
            "1. Rotate the API key in the service's dashboard.\n"
            "2. Store in environment variables or a secrets manager.\n"
            "3. Use .env files locally and never commit them."
        ),
    ),
    SecretPattern(
        name="Generic Secret",
        regex=r'(?i)(secret[_\-\s]?key|app[_\-\s]?secret|client[_\-\s]?secret)["\s]*[=:]+[\s"\']*([0-9a-zA-Z\-_+/]{24,})["\']?',
        severity="HIGH",
        format_specific=False,
        remediation=(
            "1. Rotate the secret.\n"
            "2. Use environment variables or a secrets manager."
        ),
    ),
    SecretPattern(
        name="Hardcoded Password",
        regex=r'(?i)(password|passwd|pwd)["\s]*[=:]+[\s"\']+([^\s"\'`]{8,})["\']',
        severity="HIGH",
        format_specific=False,
        remediation=(
            "1. Change the password immediately in the target system.\n"
            "2. Store passwords in environment variables or a vault.\n"
            "3. Use bcrypt/argon2 for password hashing — never store plaintext passwords."
        ),
    ),
    SecretPattern(
        name="Azure Storage Key",
        regex=r"[Aa]ccount[Kk]ey=[A-Za-z0-9+/=]{88}",
        severity="CRITICAL",
        format_specific=True,
        remediation=(
            "1. Rotate the key in Azure Portal → Storage Account → Access Keys.\n"
            "2. Use Azure Managed Identities instead of storage keys."
        ),
    ),
    SecretPattern(
        name="Azure SAS Token",
        regex=r"sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&(ss|spr|sig)=",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke the SAS token by rotating the storage account key.\n"
            "2. Use short-lived SAS tokens with minimum required permissions."
        ),
    ),
    SecretPattern(
        name="npm Auth Token",
        regex=r"//registry\.npmjs\.org/:_authToken=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke the token at npmjs.com/settings/tokens.\n"
            "2. Add .npmrc to .gitignore.\n"
            "3. Use CI/CD environment variables for npm auth."
        ),
    ),
    SecretPattern(
        name="PyPI API Token",
        regex=r"pypi-[A-Za-z0-9_\-]{50,}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke the token at pypi.org/manage/account/token/.\n"
            "2. Use CI/CD secrets for publishing."
        ),
    ),
    SecretPattern(
        name="Discord Bot Token",
        regex=r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Regenerate the token in Discord Developer Portal.\n"
            "2. Store in environment variables."
        ),
    ),
    SecretPattern(
        name="Mailgun API Key",
        regex=r"key-[0-9a-zA-Z]{32}",
        severity="HIGH",
        format_specific=True,
        remediation=(
            "1. Revoke the key in Mailgun dashboard → API Keys.\n"
            "2. Store in environment variables."
        ),
    ),
]

PLACEHOLDER_PATTERNS = [
    r"(xxx|XXX){3,}",
    r"(?i)\b(example|sample|demo|fake|mock|dummy|placeholder|changeme|change.?me|test)",
    r"(?i)your.{0,5}(key|token|secret|password|api|value|credential)",
    r"(?i)(key|token|secret|password).{0,5}here\b",
    r"<[^>]{3,}>",
    r"\$\{[^}]+\}",
    r"%[^%]{2,}%",
    r"\{\{[^}]+\}\}",
    r"(?i)\b(insert|replace|fill|todo|changeme)\b",
    r"^[a-z]+$",   # bare lowercase word like "password" or "secret"
    r"^\*+$",
    r"^=+$",
    r"(?i)_here$",  # ends with _here or -here
    r"(?i)-here$",
]

TEST_FILE_PATTERNS = [
    r"/tests?/",
    r"/spec(s)?/",
    r"\.test\.",
    r"\.spec\.",
    r"_test\.",
    r"_spec\.",
    r"/fixtures?/",
    r"/mock(s)?/",
    r"test_\w+\.py",
]


def is_placeholder(text: str) -> bool:
    for p in PLACEHOLDER_PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            return True
    if len(text) < 8:
        return True
    unique_ratio = len(set(text.lower())) / len(text)
    if unique_ratio < 0.3:
        return True
    return False


def is_test_file(file_path: str) -> bool:
    for p in TEST_FILE_PATTERNS:
        if re.search(p, file_path, re.IGNORECASE):
            return True
    return False
