"""Interface de linha de comando."""
from __future__ import annotations

import argparse
import logging
from dataclasses import replace
from pathlib import Path

from .alerts import make_alerts, write_alerts
from .config import Settings
from .context_db import ContextDB
from .pipeline import run


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="soc_triage", description=__doc__)
    ap.add_argument("cmd", choices=["init", "gen", "run", "all"],
                    help="init: recria o BD | gen: gera alertas | run: analisa | all: tudo")
    ap.add_argument("--dry-run", action="store_true", help="monta os prompts sem chamar a LLM")
    ap.add_argument("--model", help="modelo do Ollama (padrão: $OLLAMA_MODEL ou qwen2.5:3b)")
    ap.add_argument("--workdir", type=Path, help="pasta de saída (padrão: lab_out)")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    overrides = {k: v for k, v in (("model", args.model), ("workdir", args.workdir)) if v}
    settings = replace(Settings(), **overrides)

    try:
        if args.cmd in ("init", "all"):
            ContextDB.create(settings.db_path, settings.history_hours).close()
        if args.cmd in ("gen", "all"):
            write_alerts(settings.alerts_path, make_alerts())
        if args.cmd in ("run", "all"):
            run(settings, dry_run=args.dry_run)
    except FileNotFoundError as e:
        logging.error("erro: %s", e)
        return 1
    return 0
