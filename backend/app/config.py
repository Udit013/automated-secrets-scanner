import os
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


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
    # Ceiling across ALL clients, a backstop for the per-IP limit: on hosts where
    # the client address can't be trusted (X-Forwarded-For spoofable) it still
    # bounds how much work anonymous visitors can queue.
    SCAN_GLOBAL_RATE_LIMIT: int = 60
    MAX_SCHEDULES: int = 25
    # Where the client address comes from. Only ever set this to a header your
    # edge overwrites on every request, never one a client can supply.
    #   CLIENT_IP_HEADER   a single-address header written by the edge
    #                      (Render sits behind Cloudflare: cf-connecting-ip).
    #                      Missing or malformed -> the request shares one
    #                      "unknown" bucket rather than falling back to
    #                      something spoofable.
    #   TRUSTED_PROXY_HOPS proxies that each append to X-Forwarded-For; the
    #                      client is the entry that many from the right.
    # With neither set the socket peer is used.
    CLIENT_IP_HEADER: str = ""
    TRUSTED_PROXY_HOPS: int = 0

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

# Render always fronts services with Cloudflare, which overwrites CF-Connecting-IP
# (measured against the live service), so that is the default there.
if not settings.CLIENT_IP_HEADER and os.environ.get("RENDER") == "true" and not settings.TRUSTED_PROXY_HOPS:
    settings.CLIENT_IP_HEADER = "cf-connecting-ip"
