"""Relatório em Markdown e JSONL."""
from __future__ import annotations

import json
from pathlib import Path

from .alerts import Alert


def render_alert(alert: Alert, ctx: dict, result: dict | None, injection: bool, elapsed: float = 0.0) -> str:
    rule = alert["rule"]
    lines = [f"## [{rule['level']}] regra {rule['id']} — {rule['description']}",
             f"- agente: {alert['agent']['name']} | {alert['timestamp']}",
             f"- contexto: `{json.dumps(ctx, ensure_ascii=False)}`"]
    if injection:
        lines.append("- **padrão de prompt injection detectado no alerta (regex)**")
    if result is None:
        lines.append("- (dry-run: LLM não chamada)")
    elif "erro" in result:
        lines.append(f"- ERRO: {result['erro']}")
        if result.get("bruto"):
            lines.append(f"- resposta bruta: `{result['bruto']}`")
    else:
        if result.get("campos_ausentes"):
            lines.append(f"- modelo omitiu: {result['campos_ausentes']}")
        lines += [f"- classificação: **{result['classificacao']}** | severidade: **{result['severidade']}**"
                  f" | tempo: {elapsed:.1f}s",
                  f"- resumo: {result['resumo']}",
                  f"- justificativa: {result['justificativa']}",
                  f"- modelo marcou injeção: {result['tentativa_injecao']}",
                  "- ações sugeridas (NÃO executadas):"]
        lines += [f"  - [{a.get('tipo')}/{a.get('risco')}] {a.get('acao')}" for a in result["acoes"]]
    return "\n".join(lines) + "\n"


def write_report(path: Path, model: str, sections: list[str], records: list[dict]) -> Path:
    path.write_text("\n".join([f"# Relatório de triagem (modelo: {model})\n", *sections]))
    path.with_suffix(".jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records))
    return path
