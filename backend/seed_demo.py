"""
Demo data seeder — run once after first deploy.
Populates the database with realistic scan history.
Safe to re-run: skips if data already exists.
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from app.database import init_db, AsyncSessionLocal
from app.models import Scan, Finding

# (severity, secret_type, masked_value, entropy, file_path, line_number)
DEMO_SCANS = [
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/payment-service",
        "days_ago": 1,
        "files": 312,
        "findings": [
            ("CRITICAL", "Stripe Live Secret Key",      "sk_live_***...***dc",    6.1, "payment/stripe.py",       12),
            ("CRITICAL", "Database Connection String",  "postgresql://***@prod***",5.9, "config/database.py",       4),
            ("CRITICAL", "AWS Access Key",              "AKIA***...***JKM",       3.8, "infra/aws_config.py",      7),
            ("HIGH",     "GitHub Personal Access Token","ghp_***...***B4a",       4.1, ".github/workflows/cd.yml", 23),
            ("HIGH",     "AWS Secret Access Key",       "wJal***...***KEY",       4.5, "infra/aws_config.py",      8),
            ("HIGH",     "JWT Token",                   "eyJ***...***R8U",        4.8, "auth/tokens.py",           19),
            ("HIGH",     "Generic Secret",              "a1b2***...***p6",        4.3, "backend/settings.py",     18),
            ("MEDIUM",   "JWT Token",                   "eyJ***...***Abc",        4.2, "tests/auth_test.py",      55),
            ("MEDIUM",   "Hardcoded Password",          "Sup3r***...***23!",      3.7, "tests/fixtures.py",        9),
            ("LOW",      "Generic API Key",             "test***...***key",       3.5, "tests/mocks.py",          44),
        ],
    },
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/data-pipeline",
        "days_ago": 4,
        "files": 178,
        "findings": [
            ("CRITICAL", "GCP Service Account Key",    '{"type":"service_account"...}', 5.5, "deploy/sa_key.json",   1),
            ("CRITICAL", "Database Connection String", "mysql://***@rds***",      5.8, "etl/db_writer.py",       14),
            ("HIGH",     "Google API Key",             "AIza***...***KL",         4.2, "scripts/geocode.py",     14),
            ("HIGH",     "Slack Bot Token",            "xoxb-***...***24",        4.0, "notify/alerts.py",        8),
            ("HIGH",     "JWT Token",                  "eyJ***...***xyz",         4.7, "api/middleware.py",      33),
            ("HIGH",     "Generic Secret",             "d4e5***...***p6",         4.3, "config/secrets.py",      21),
            ("MEDIUM",   "AWS Secret Access Key",      "wJal***...***EY",         4.5, "aws_utils.py",           19),
            ("MEDIUM",   "Generic API Key",            "a1b2***...***56",         3.8, "connectors/kafka.py",    31),
            ("LOW",      "Hardcoded Password",         "devp***...***321",        3.5, "scripts/migrate.py",     77),
        ],
    },
    {
        "source_type": "paste",
        "source_ref": "paste",
        "days_ago": 6,
        "files": 1,
        "findings": [
            ("CRITICAL", "Private SSH Key",            "-----BEGIN RSA PRIVATE***",5.2, "paste",   1),
            ("HIGH",     "SendGrid API Key",            "SG.***...***43",          4.6, "paste",   3),
            ("HIGH",     "JWT Token",                   "eyJ***...***tok",         4.8, "paste",   7),
            ("MEDIUM",   "Twilio API Key",              "SK***...***32",           4.1, "paste",  12),
            ("MEDIUM",   "Generic Secret",              "f6g7***...***q6",         3.9, "paste",  18),
        ],
    },
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/mobile-backend",
        "days_ago": 9,
        "files": 224,
        "findings": [
            ("CRITICAL", "AWS Access Key",             "AKIA***...***XYZ",        3.9, "cloud/lambda.py",          3),
            ("HIGH",     "Discord Bot Token",          "MNA***...***27",          4.3, "bot/main.py",              5),
            ("HIGH",     "JWT Token",                  "eyJ***...***mob",         4.8, "auth/middleware.py",      22),
            ("HIGH",     "Google API Key",             "AIza***...***MN",         4.1, "maps/location.py",        11),
            ("HIGH",     "Slack Bot Token",            "xoxb-***...***mob",       4.0, "notify/push.py",          16),
            ("MEDIUM",   "Generic Secret",             "h8i9***...***p6",         3.9, "config/app.py",           17),
            ("MEDIUM",   "Generic API Key",            "j0k1***...***api",        3.8, "integrations/stripe.py",  28),
            ("LOW",      "Hardcoded Password",         "Myp@***...***24",         3.5, "tests/seed.py",           41),
        ],
    },
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/infrastructure",
        "days_ago": 15,
        "files": 89,
        "findings": [
            ("CRITICAL", "AWS Access Key",             "AKIA***...***TF1",        3.8, "terraform/main.tf",        3),
            ("CRITICAL", "Private SSH Key",            "-----BEGIN RSA PRIVATE***",5.1, "keys/bastion_key",        1),
            ("CRITICAL", "Database Connection String", "postgres://***@aurora***", 5.7, "terraform/rds.tf",        9),
            ("HIGH",     "Azure Storage Key",          "Account***...***Key=",    5.0, "azure/storage.tf",         9),
            ("HIGH",     "AWS Secret Access Key",      "m4n5***...***KEY",        4.4, "terraform/main.tf",        4),
            ("MEDIUM",   "Generic API Key",            "o5p6***...***tf",         3.8, "terraform/vars.tf",       22),
        ],
    },
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/auth-service",
        "days_ago": 22,
        "files": 156,
        "findings": [
            ("CRITICAL", "Private SSH Key",            "-----BEGIN EC PRIVATE***", 5.3, "certs/service.key",       1),
            ("HIGH",     "JWT Token",                  "eyJ***...***auth",        4.9, "src/jwt_helper.py",        8),
            ("HIGH",     "JWT Token",                  "eyJ***...***ref",         4.7, "src/refresh.py",          14),
            ("HIGH",     "Generic Secret",             "q7r8***...***sec",        4.2, "config/jwt_config.py",    31),
            ("MEDIUM",   "Hardcoded Password",         "Auth***...***321!",       3.8, "tests/test_login.py",     19),
            ("LOW",      "Generic API Key",            "test***...***api",        3.6, "tests/conftest.py",       55),
        ],
    },
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/api-gateway",
        "days_ago": 30,
        "files": 201,
        "findings": [],  # clean — shows the tool also correctly identifies safe repos
    },
]

REMEDIATION = {
    "Stripe Live Secret Key":      "1. Revoke in Stripe Dashboard → API Keys.\n2. Store in environment variable.",
    "Database Connection String":  "1. Rotate DB password immediately.\n2. Use a secrets manager (AWS Secrets Manager, Vault).",
    "GitHub Personal Access Token":"1. Revoke at github.com/settings/tokens.\n2. Use fine-grained tokens with minimum scope.",
    "AWS Access Key":              "1. Revoke in AWS IAM Console.\n2. Use IAM roles instead of long-lived credentials.",
    "AWS Secret Access Key":       "1. Rotate the access key pair in IAM.\n2. Never store in source code.",
    "Generic Secret":              "1. Rotate the secret.\n2. Store in environment variable or secrets manager.",
    "JWT Token":                   "1. Rotate the signing secret immediately.\n2. JWTs must be generated at runtime.",
    "Hardcoded Password":          "1. Change the password in the target system.\n2. Use environment variables.",
    "GCP Service Account Key":     "1. Delete the key in GCP IAM Console.\n2. Use Workload Identity Federation.",
    "Google API Key":              "1. Revoke in Google Cloud Console → Credentials.\n2. Create restricted key.",
    "Slack Bot Token":             "1. Revoke at api.slack.com/apps.\n2. Store in environment variable.",
    "Generic API Key":             "1. Rotate in the service dashboard.\n2. Store in environment variable.",
    "Private SSH Key":             "1. Remove from all authorized_keys files.\n2. Generate new key: ssh-keygen -t ed25519.",
    "SendGrid API Key":            "1. Revoke at app.sendgrid.com → Settings → API Keys.",
    "Twilio API Key":              "1. Revoke at console.twilio.com.",
    "Discord Bot Token":           "1. Regenerate in Discord Developer Portal.",
    "Azure Storage Key":           "1. Rotate in Azure Portal → Storage Account → Access Keys.\n2. Use Managed Identity.",
}


async def seed():
    await init_db()
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select, func
        count = (await db.execute(select(func.count(Scan.id)))).scalar_one()
        if count >= len(DEMO_SCANS):
            print(f"Already seeded ({count} scans). Skipping.")
            return

        now = datetime.now(timezone.utc)
        total_findings = 0

        for s in DEMO_SCANS:
            created = now - timedelta(days=s["days_ago"])
            completed = created + timedelta(seconds=max(8, len(s["findings"]) * 3))

            scan = Scan(
                id=str(uuid.uuid4()),
                source_type=s["source_type"],
                source_ref=s["source_ref"],
                status="completed",
                total_findings=len(s["findings"]),
                files_scanned=s["files"],
                progress=100,
                created_at=created,
                completed_at=completed,
            )
            db.add(scan)
            await db.flush()

            for sev, stype, masked, entropy, fpath, line in s["findings"]:
                db.add(Finding(
                    id=str(uuid.uuid4()),
                    scan_id=scan.id,
                    file_path=fpath,
                    line_number=line,
                    secret_type=stype,
                    matched_string=masked,
                    entropy=entropy,
                    severity=sev,
                    confidence="HIGH" if entropy > 4.5 else "MEDIUM",
                    context=f'{stype.lower().replace(" ", "_")} = "{masked}"',
                    remediation=REMEDIATION.get(stype, "Rotate and store in environment variable."),
                    is_in_history=False,
                ))
                total_findings += 1

        await db.commit()
        print(f"Seeded {len(DEMO_SCANS)} scans with {total_findings} findings.")


if __name__ == "__main__":
    asyncio.run(seed())
