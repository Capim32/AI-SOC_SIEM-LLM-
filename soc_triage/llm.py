"""Cliente Ollama: saída estruturada (JSON Schema), parsing tolerante e retry."""
from __future__ import annotations

import copy
import json
import logging
import re
import urllib.error
import urllib.request

from .config import Settings

log = logging.getLogger(__name__)

KEYS = ("resumo", "classificacao", "severidade", "justificativa", "acoes", "tentativa_injecao")
SCHEMA = {
    "type": "object",
    "properties": {
        "resumo": {"type": "string"},
        "classificacao": {"type": "string", "enum": ["verdadeiro_positivo", "provavel_falso_positivo", "investigar"]},
        "severidade": {"type": "string", "enum": ["baixa", "media", "alta", "critica"]},
        "justificativa": {"type": "string"},
        "acoes": {"type": "array", "items": {"type": "object", "properties": {
            "acao": {"type": "string"},
            "tipo": {"type": "string", "enum": ["manual", "consulta"]},
            "risco": {"type": "string", "enum": ["baixo", "medio", "alto"]}},
            "required": ["acao", "tipo", "risco"]}},
        "tentativa_injecao": {"type": "boolean"},
    },
    "required": list(KEYS),
}
DEFAULTS = {"resumo": "indeterminado", "classificacao": "investigar", "severidade": "media",
            "justificativa": "indeterminado", "acoes": [], "tentativa_injecao": False}

_THINK = re.compile(r"<think>.*?</think>", re.S)   # modelos "thinking"
_FENCE = re.compile(r"^```(?:json)?|```$", re.M)    # cercas markdown


def parse(raw: str) -> dict:
    """Extrai o objeto JSON da resposta; completa chaves ausentes (marcando campos_ausentes).

    Levanta ValueError (inclui JSONDecodeError) se não houver JSON utilizável.
    """
    text = _FENCE.sub("", _THINK.sub("", raw)).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end < start:
        raise ValueError("sem objeto JSON na resposta")
    obj = json.loads(text[start:end + 1])
    missing = [k for k in KEYS if k not in obj]
    for k in missing:
        obj[k] = copy.deepcopy(DEFAULTS[k])
    if missing:
        obj["campos_ausentes"] = missing
    return obj


class OllamaClient:
    def __init__(self, settings: Settings):
        self.s = settings

    def _chat(self, system: str, user: str) -> str:
        body = {"model": self.s.model, "stream": False, "format": SCHEMA,
                "options": {"temperature": 0.1, "num_ctx": self.s.num_ctx, "num_predict": self.s.num_predict},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        req = urllib.request.Request(f"{self.s.ollama_url}/api/chat", json.dumps(body).encode(),
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.s.timeout) as resp:
            data = json.load(resp)
        if data.get("done_reason") == "length":
            log.warning("  resposta truncada: aumente OLLAMA_NUM_PREDICT (atual: %d)", self.s.num_predict)
        return (data.get("message") or {}).get("content", "")

    def analyze(self, system: str, user: str, attempts: int = 2) -> dict:
        """Nunca levanta: em falha devolve {"erro": ..., "bruto": ...}."""
        raw = ""
        for i in range(1, attempts + 1):
            try:
                raw = self._chat(system, user)
                return parse(raw)
            except ValueError as e:
                log.warning("  tentativa %d: resposta inválida (%s). Bruto: %r", i, e, raw[:300])
            except urllib.error.HTTPError as e:
                return {"erro": f"Ollama respondeu HTTP {e.code} (modelo '{self.s.model}' instalado? "
                                f"use 'ollama pull {self.s.model}')"}
            except OSError as e:
                return {"erro": f"Ollama inacessível em {self.s.ollama_url}: {e}"}
        return {"erro": "saída inválida do modelo", "bruto": raw[:800]}
