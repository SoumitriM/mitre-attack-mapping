from functools import lru_cache
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or a local .env file."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    nvd_api_key: str | None = None
    http_timeout_seconds: float = Field(default=15.0, gt=0)
    http_max_retries: int = Field(default=3, ge=0, le=10)
    cache_ttl_seconds: int = Field(default=3600, ge=0)
    mapping_min_confidence: float = Field(default=0.75, ge=0, le=1)
    validation_min_confidence: float = Field(default=0.5, ge=0, le=1)
    advisory_allowed_domains: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["offseq.com"]
    )
    advisory_max_bytes: int = Field(default=2_000_000, gt=0)
    fh_genie_key: SecretStr | None = None
    fh_genie_base_url: str | None = None
    fh_genie_model: str | None = None
    fh_genie_embedding_model: str = "BAAI/bge-m3"
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
