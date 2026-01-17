"""
Application configuration using Pydantic Settings.
"""
from functools import lru_cache
from typing import Optional

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

    # API settings
    api_prefix: str = "/api/v1"

    # CORS settings
    cors_origins: list[str] = ["http://localhost:4200", "http://localhost:3000"]

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
