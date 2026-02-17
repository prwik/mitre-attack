"""
Application configuration using Pydantic Settings.
"""
import json
from functools import lru_cache
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application settings
    app_name: str = "MITRE ATT&CK Navigator API"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"

    # API settings
    api_prefix: str = "/api/v1"

    # CORS settings
    cors_origins: list[str] = ["http://localhost:4200", "http://localhost:3000"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Handle both comma-separated strings and JSON arrays from env."""
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                try:
                    return json.loads(v)
                except json.JSONDecodeError:
                    pass
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    # ReliaQuest API settings
    reliaquest_api_key: str = ""
    reliaquest_api_url: str = "https://api.myreliaquest.com/graphql"

    # Mock data for development
    use_mock_data: bool = True

    # Navigator settings
    default_domain: str = "enterprise-attack"
    cache_ttl: int = 300  # 5 minutes


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
