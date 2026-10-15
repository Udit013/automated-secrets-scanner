from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./secrets_scanner.db"
    GITHUB_TOKEN: str = ""

    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    ALERT_EMAIL: str = ""

    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"
    BACKEND_URL: str = "http://localhost:8000"

    # --- Access control -------------------------------------------------
    # Unset: open demo mode (every endpoint public, abuse-limited below).
    # Set: private workspace mode — every /api/v1 request must send
    # `Authorization: Bearer <ACCESS_TOKEN>`. Use a long random value.
    ACCESS_TOKEN: str = ""

    # HMAC key for credential fingerprints. If unset, one is generated on
    # first boot and stored in the database. Set it in production so the key
    # does not live beside the data it protects.
    FINGERPRINT_KEY: str = ""

    # --- Abuse limits ---------------------------------------------------
    SCAN_RATE_LIMIT: int = 10            # new scans per client per window
    SCAN_RATE_WINDOW_SECONDS: int = 600
    MAX_CONCURRENT_SCANS: int = 3        # protects a 512 MB free-tier instance
    MAX_SCHEDULES: int = 25
    # Number of reverse proxies in front of the app (Render: 1). Used to read
    # the real client IP from X-Forwarded-For; 0 trusts only the socket peer.
    TRUSTED_PROXY_HOPS: int = 0

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
