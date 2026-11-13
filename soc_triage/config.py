"""Configuração central: variáveis de ambiente com valores padrão."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


@dataclass(frozen=True)
class Settings:
    ollama_url: str = field(default_factory=lambda: _env("OLLAMA_URL", "http://localhost:11434").rstrip("/"))
    model: str = field(default_factory=lambda: _env("OLLAMA_MODEL", "llama3.2"))
    num_ctx: int = field(default_factory=lambda: int(_env("OLLAMA_NUM_CTX", "4096")))
    num_predict: int = field(default_factory=lambda: int(_env("OLLAMA_NUM_PREDICT", "512")))
    timeout: int = field(default_factory=lambda: int(_env("OLLAMA_TIMEOUT", "300")))
    workdir: Path = Path("lab_out")
    history_hours: int = 24      # janela de correlação por IP
    max_log_chars: int = 1500    # corte do full_log enviado ao modelo

    @property
    def alerts_path(self) -> Path:
        return self.workdir / "alerts.ndjson"

    @property
    def db_path(self) -> Path:
        return self.workdir / "context.db"
