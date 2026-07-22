from __future__ import annotations
import os
from enum import Enum
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class LLMProvider(str, Enum):
    GEMINI = "gemini"
    OPENAI = "openai"
    MOCK = "mock"


class Settings(BaseSettings):
    """Application global settings and LLM configuration."""
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application settings
    APP_NAME: str = "AI-Augmented Recon & Attack Surface Analyser"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    PORT: int = Field(default=8000, alias="PORT")
    HOST: str = Field(default="0.0.0.0", alias="HOST")

    # LLM Settings
    GEMINI_API_KEY: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")
    OPENAI_API_KEY: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    LLM_PROVIDER: LLMProvider = Field(default=LLMProvider.MOCK, alias="LLM_PROVIDER")
    GEMINI_MODEL: str = "gemini-2.5-pro"
    OPENAI_MODEL: str = "gpt-4o"

    # RAG Vector Store Settings
    EMBEDDING_MODEL_NAME: str = "all-MiniLM-L6-v2"
    RAG_TOP_K: int = 3
    SIMILARITY_THRESHOLD: float = 0.35

    # Scanner Settings
    SCAN_TIMEOUT_SECONDS: int = 15
    MAX_PORTS_TO_SCAN: int = 20
    ALLOW_INTERNAL_IPS: bool = True  # Set to True for local testing & demos

    def get_active_provider(self) -> LLMProvider:
        """Determine active LLM provider based on config or available API keys."""
        if self.LLM_PROVIDER != LLMProvider.MOCK:
            return self.LLM_PROVIDER
        if self.GEMINI_API_KEY:
            return LLMProvider.GEMINI
        if self.OPENAI_API_KEY:
            return LLMProvider.OPENAI
        return LLMProvider.MOCK


settings = Settings()
