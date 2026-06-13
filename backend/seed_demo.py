"""
Demo data seeder — run once after first deploy.
Populates the database with realistic scan history so the dashboard
looks production-grade when a recruiter opens it.

Usage:
  python seed_demo.py
"""

import asyncio
import uuid
from datetime import datetime, timedelta
from app.database import init_db, AsyncSessionLocal
from app.models import Scan, Finding

DEMO_SCANS = [
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/payment-service",
        "days_ago": 1,
        "findings": [
            ("CRITICAL", "Stripe Live Secret Key",     "sk_live_***...***dc",   6.1, "payment/config.py",  12),
            ("CRITICAL", "Database Connection String",  "postgresql://***@***",  5.9, "config/db.py",       4),
            ("HIGH",     "GitHub Personal Access Token","ghp_***...***B4a",     4.1, ".github/deploy.yml", 23),
            ("HIGH",     "AWS Access Key",              "AKIA***...***JKM",     3.7, "infra/terraform.tf", 7),
            ("HIGH",     "Generic Secret",              "a1b2***...***p6",      4.3, "backend/settings.py",18),
            ("MEDIUM",   "JWT Token",                   "eyJ***...***R8U",      4.8, "tests/auth_test.py", 55),
            ("LOW",      "Hardcoded Password",          "supe***...***23!",     3.6, "tests/fixtures.py",  9),
        ],
    },
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/data-pipeline",
        "days_ago": 3,
        "findings": [
            ("CRITICAL", "GCP Service Account Key",    '{"type":"service_account"...}', 5.5, "deploy/sa_key.json", 1),
            ("HIGH",     "Google API Key",             "AIza***...***KL",       4.2, "scripts/geocode.py", 14),
            ("HIGH",     "Slack Bot Token",            "xoxb-***...***24",      4.0, "notify/slack.py",    8),
            ("MEDIUM",   "Generic API Key",            "a1b2***...***56",       3.8, "etl/connectors.py",  31),
            ("MEDIUM",   "AWS Secret Access Key",      "wJal***...***EY",       4.5, "aws_utils.py",       19),
        ],
    },
    {
        "source_type": "paste",
        "source_ref": "paste",
        "days_ago": 5,
        "findings": [
            ("HIGH",     "Private SSH Key",            "-----BEGIN RSA***",     5.2, "paste",               1),
            ("HIGH",     "SendGrid API Key",           "SG.***...***43",        4.6, "paste",               3),
            ("MEDIUM",   "Twilio API Key",             "SK***...***32",         4.1, "paste",               7),
        ],
    },
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/mobile-backend",
        "days_ago": 8,
        "findings": [
            ("HIGH",     "Discord Bot Token",          "MNA***...***27",        4.3, "bot/main.py",         5),
            ("HIGH",     "JWT Token",                  "eyJ***...***R8U",       4.8, "auth/middleware.py",  22),
            ("MEDIUM",   "Generic Secret",             "d4e5***...***p6",       3.9, "config/app.py",       17),
            ("LOW",      "Hardcoded Password",         "Myp@***...***24",       3.5, "tests/seed.py",       41),
        ],
    },
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/infrastructure",
        "days_ago": 14,
        "findings": [
            ("CRITICAL", "AWS Access Key",             "AKIAV***...***JKM",    3.8, "terraform/vars.tf",    3),
            ("CRITICAL", "Private SSH Key",            "-----BEGIN RSA***",     5.1, "keys/deploy_key",     1),
            ("HIGH",     "Azure Storage Key",          "Account***...***=",     5.0, "azure/config.tf",     9),
        ],
    },
    {
        "source_type": "github",
        "source_ref": "https://github.com/acme-corp/api-gateway",
        "days_ago": 21,
        "findings": [],  # clean scan
    },
]

REMEDIATION = {
    "Stripe Live Secret Key": "1. Revoke in Stripe Dashboard → Developers → API Keys.\n2. Rotate and store in environment variable.",
    "Database Connection String": "1. Rotate the database password.\n2. Store in environment variable or secrets manager.",
    "GitHub Personal Access Token": "1. Revoke at github.com/settings/tokens.\n2. Use fine-grained tokens with minimum scope.",
    "AWS Access Key": "1. Revoke in AWS IAM Console.\n2. Rotate key pair.\n3. Use IAM roles instead.",
    "Generic Secret": "1. Rotate the secret.\n2. Store in environment variable.",
    "JWT Token": "1. Rotate the signing secret.\n2. JWTs should be generated at runtime, never hardcoded.",
    "Hardcoded Password": "1. Change the password in the target system.\n2. Use environment variables.",
    "GCP Service Account Key": "1. Delete the key in GCP IAM Console.\n2. Use Workload Identity Federation.",
    "Google API Key": "1. Revoke in Google Cloud Console → Credentials.\n2. Create restricted key.",
    "Slack Bot Token": "1. Revoke at api.slack.com/apps.\n2. Store in environment variable.",
    "Generic API Key": "1. Rotate in the service dashboard.\n2. Store in environment variable.",
    "AWS Secret Access Key": "1. Revoke in AWS IAM Console.\n2. Rotate the access key pair.",
    "Private SSH Key": "1. Remove from authorized_keys.\n2. Generate new key pair: ssh-keygen -t ed25519.",
    "SendGrid API Key": "1. Revoke at app.sendgrid.com → Settings → API Keys.\n2. Create key with minimum permissions.",
    "Twilio API Key": "1. Revoke at console.twilio.com.\n2. Store in environment variable.",
    "Discord Bot Token": "1. Regenerate in Discord Developer Portal.\n2. Store in environment variable.",
    "Azure Storage Key": "1. Rotate in Azure Portal → Storage Account → Access Keys.\n2. Use Managed Identity.",
}


async def seed():
    await init_db()
    async with AsyncSessionLocal() as db:
        # Check if already seeded
        from sqlalchemy import select, func
        count = (await db.execute(select(func.count(Scan.id)))).scalar_one()
        if count >= len(DEMO_SCANS):
            print(f"Already seeded ({count} scans). Skipping.")
            return

        now = datetime.utcnow()
        total_findings = 0

        for s in DEMO_SCANS:
            created = now - timedelta(days=s["days_ago"])
            completed = created + timedelta(seconds=max(5, len(s["findings"]) * 2))

            scan = Scan(
                id=str(uuid.uuid4()),
                source_type=s["source_type"],
                source_ref=s["source_ref"],
                status="completed",
                total_findings=len(s["findings"]),
                files_scanned=max(1, len(s["findings"]) * 7),
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
