"""Orquestra: alerta -> contexto -> prompt -> LLM -> relatório."""
from __future__ import annotations

import logging
import time
from datetime import datetime
from pathlib import Path

from .alerts import load_alerts
from .config import Settings
from .context_db import ContextDB
from .llm import OllamaClient
from .prompt import SYSTEM, build_user_prompt
from .report import render_alert, write_report
from .security import looks_like_injection

log = logging.getLogger(__name__)


def run(settings: Settings, dry_run: bool = False) -> Path:
    if not (settings.alerts_path.exists() and settings.db_path.exists()):
        raise FileNotFoundError("alertas ou BD ausentes: rode 'init' e 'gen' antes (ou use 'all').")
    client = None if dry_run else OllamaClient(settings)
    sections, records = [], []

    with ContextDB(settings.db_path, settings.history_hours) as db:
        for alert in load_alerts(settings.alerts_path):
            rule_id, agent = alert["rule"]["id"], alert["agent"]["name"]
            log.info("regra %s @ %s%s", rule_id, agent, " [dry-run]" if dry_run else "")
            ctx = db.build_context(alert)
            injection = looks_like_injection(alert)
            prompt = build_user_prompt(alert, ctx, settings.max_log_chars)

            t0 = time.perf_counter()
            result = None if dry_run else client.analyze(SYSTEM, prompt)
            elapsed = time.perf_counter() - t0

            if dry_run:
                log.info("  prompt: %s ...", prompt[:300])
            sections.append(render_alert(alert, ctx, result, injection, elapsed))
            records.append({"rule_id": rule_id, "agent": agent, "timestamp": alert["timestamp"],
                            "contexto": ctx, "injecao_regex": injection,
                            "resultado": result, "tempo_s": round(elapsed, 2)})
            db.record(alert)

    out = settings.workdir / f"report_{datetime.now():%Y%m%d_%H%M%S}.md"
    write_report(out, settings.model, sections, records)
    log.info("relatório: %s", out)
    return out
