"""
Application configuration using Pydantic Settings.
"""
import json
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
    log_level: str = "INFO"

    # API settings
    api_prefix: str = "/api/v1"

    # CORS settings - stored as str to avoid pydantic-settings env parsing issues
    cors_origins: str = "http://localhost:4200,http://localhost:3000"

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS origins from string (comma-separated or JSON array)."""
        v = self.cors_origins.strip()
        if v.startswith("["):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                pass
        return [origin.strip() for origin in v.split(",") if origin.strip()]

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
