from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or a local .env file."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    nvd_api_key: str | None = None
    http_timeout_seconds: float = Field(default=15.0, gt=0)
    http_max_retries: int = Field(default=3, ge=0, le=10)
    cache_ttl_seconds: int = Field(default=3600, ge=0)
    cvelist_v5_root: Path = Path("data/raw/cvelist-v5")
    advisory_allowed_domains: list[str] = Field(default_factory=lambda: ["offseq.com"])
    advisory_max_bytes: int = Field(default=2_000_000, gt=0)
    fh_genie_key: SecretStr | None = None
    fh_genie_base_url: str | None = None
    fh_genie_model: str | None = None
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_username: str = "neo4j"
    neo4j_password: SecretStr | None = None

    @field_validator("advisory_allowed_domains", mode="before")
    @classmethod
    def split_domains(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip().lower() for item in value.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
