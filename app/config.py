from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or a local .env file."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    nvd_api_key: str | None = None
    http_timeout_seconds: float = Field(default=15.0, gt=0)
    http_max_retries: int = Field(default=3, ge=0, le=10)
    mapping_min_confidence: float = Field(default=0.50, ge=0, le=1)
    validation_min_confidence: float = Field(default=0.5, ge=0, le=1)
    enable_llm_validation: bool = False
    enable_ctid_mapping: bool = True
    ctid_only_mode: bool = False
    llm_validation_confidence_threshold: float = Field(default=0.8, ge=0, le=1)
    advisory_allowed_domains: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["offseq.com"]
    )
    advisory_max_bytes: int = Field(default=2_000_000, gt=0)
    fh_genie_key: SecretStr | None = None
    fh_genie_base_url: str | None = None
    fh_genie_model: str | None = "MiniMaxAI/MiniMax-M2.5"
    fh_genie_embedding_model: str = "BAAI/bge-m3"
    attack_embedding_cache_path: Path = Path("data/cache/attack-embeddings.json")
    inference_provider: Literal["fh_genie", "openrouter"] = "fh_genie"
    openrouter_key: SecretStr | None = None
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "anthropic/claude-opus-4.6"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_username: str = "neo4j"
    neo4j_password: SecretStr | None = None

    @property
    def inference_model(self) -> str | None:
        if self.inference_provider == "openrouter":
            return self.openrouter_model
        return self.fh_genie_model

    @property
    def inference_key(self) -> SecretStr | None:
        if self.inference_provider == "openrouter":
            return self.openrouter_key
        return self.fh_genie_key

    @property
    def inference_base_url(self) -> str | None:
        if self.inference_provider == "openrouter":
            return self.openrouter_base_url
        return self.fh_genie_base_url

    @property
    def downstream_model(self) -> str | None:
        return self.fh_genie_model

    @field_validator("advisory_allowed_domains", mode="before")
    @classmethod
    def split_domains(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip().lower() for item in value.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
