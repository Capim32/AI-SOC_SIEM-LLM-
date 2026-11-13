"""BD de contexto (SQLite): ativos, reputação de IP, playbooks e histórico de correlação."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .alerts import Alert, source_ip

DDL = """
create table assets(agent_name text primary key, papel text, criticidade text, dono text, exposicao text, notas text);
create table ioc(ip text primary key, tag text, nota text);
create table playbooks(rule_id text primary key, titulo text, passos text);
create table history(ts text, srcip text, agent text, rule_id text);
create index idx_history_ip_ts on history(srcip, ts);
"""

ASSETS = [
    ("web-01", "servidor web", "alta", "equipe-web", "internet", "SSH deveria aceitar só chave, sem root"),
    ("db-01", "banco PostgreSQL", "critica", "dba", "interna", "/etc/passwd só muda em janela de manutenção (sáb 02h)"),
    ("k8s-node-1", "worker kubernetes", "alta", "plataforma", "interna", ""),
    ("dev-ws-07", "estação de desenvolvimento", "baixa", "dev1", "interna", "sudo apt/pip é rotina dos devs"),
]
IOCS = [("203.0.113.50", "scanner-conhecido", "IP fictício de teste, visto em varreduras SSH")]
PLAYBOOKS = [
    ("5763", "Brute force SSH", "1) checar se houve login bem-sucedido do mesmo IP; 2) verificar PermitRootLogin; "
                                "3) considerar bloqueio no firewall (aprovação humana)"),
    ("31103", "SQL injection", "1) verificar status HTTP e tamanho da resposta; 2) revisar logs do app/BD; 3) avaliar regra de WAF"),
    ("550", "Mudança em arquivo crítico", "1) comparar com janela de manutenção; 2) checar quem alterou (auditd); "
                                           "3) restaurar de baseline se não autorizado"),
    ("5402", "sudo para root", "Rotina para devs; investigar só se comando incomum"),
    ("86601", "Alerta Suricata", "Correlacionar IP de origem com outros alertas das últimas 24h"),
]


class ContextDB:
    def __init__(self, path: Path, history_hours: int = 24):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.history_hours = history_hours

    @classmethod
    def create(cls, path: Path, history_hours: int = 24) -> "ContextDB":
        """Recria o BD do zero (apaga histórico anterior) e carrega os dados de exemplo."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        db = cls(path, history_hours)
        db.conn.executescript(DDL)
        db.conn.executemany("insert into assets values(?,?,?,?,?,?)", ASSETS)
        db.conn.executemany("insert into ioc values(?,?,?)", IOCS)
        db.conn.executemany("insert into playbooks values(?,?,?)", PLAYBOOKS)
        db.conn.commit()
        return db

    def __enter__(self) -> "ContextDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    def _one(self, sql: str, args: tuple = ()) -> Optional[dict]:
        row = self.conn.execute(sql, args).fetchone()
        return dict(row) if row else None

    def build_context(self, alert: Alert) -> dict:
        """Consultas parametrizadas: o conteúdo do alerta nunca é concatenado em SQL."""
        ctx = {"ativo": self._one("select papel,criticidade,dono,exposicao,notas from assets where agent_name=?",
                                  (alert["agent"]["name"],)) or "desconhecido"}
        ip = source_ip(alert)
        if ip:
            ctx["reputacao_ip"] = self._one("select tag,nota from ioc where ip=?", (ip,)) or "sem registro"
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=self.history_hours)).isoformat()
            ctx["correlacao_24h"] = [dict(r) for r in self.conn.execute(
                "select agent as agente, rule_id as regra, ts as quando from history where srcip=? and ts>?",
                (ip, cutoff))]
        ctx["playbook"] = self._one("select titulo,passos from playbooks where rule_id=?",
                                    (alert["rule"]["id"],)) or "nenhum"
        return ctx

    def record(self, alert: Alert) -> None:
        """Registra o alerta no histórico (depois da análise, para não correlacionar consigo mesmo)."""
        ip = source_ip(alert)
        if ip:
            self.conn.execute("insert into history values(?,?,?,?)",
                              (datetime.now(timezone.utc).isoformat(), ip,
                               alert["agent"]["name"], alert["rule"]["id"]))
            self.conn.commit()
