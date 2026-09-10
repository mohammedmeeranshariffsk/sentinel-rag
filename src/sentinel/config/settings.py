from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    apktool_path: Path
    jadx_path: Path

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()


class AnalysisOptions(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='SENTINEL_', extra='ignore')
    graph_depth: int = Field(default=1, ge=0, le=3)
    graph_node_limit: int = Field(default=500, ge=1, le=500)
    graph_method_limit: int = Field(default=40, ge=1, le=40)
    behavior_seed_budget: int = Field(default=12, ge=1, le=40)
    retrieval_top_k: int = Field(default=3, ge=1, le=5)
    embedding_dimensions: int = Field(default=768, ge=128, le=3072)
    reasoning_enabled: bool = True
    rag_enabled: bool = True
