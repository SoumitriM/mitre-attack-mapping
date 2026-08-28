from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or a local .env file."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    nvd_api_key: str | None = None
    http_timeout_seconds: float = Field(default=15.0, gt=0)
    http_max_retries: int = Field(default=3, ge=0, le=10)
    cache_ttl_seconds: int = Field(default=3600, ge=0)


@lru_cache
def get_settings() -> Settings:
    return Settings()
