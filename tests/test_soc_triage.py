import tempfile
import unittest
from pathlib import Path

from soc_triage.alerts import make_alerts
from soc_triage.context_db import ContextDB
from soc_triage.llm import parse
from soc_triage.security import looks_like_injection


class ParseTests(unittest.TestCase):
    def test_fenced_and_partial_json_is_completed(self):
        out = parse('```json\n{"resumo":"ok","severidade":"alta"}\n```')
        self.assertEqual(out["resumo"], "ok")
        self.assertIn("acoes", out["campos_ausentes"])
        self.assertEqual(out["acoes"], [])

    def test_think_block_and_surrounding_text(self):
        out = parse('<think>hmm</think> Aqui: {"resumo":"x"} fim')
        self.assertEqual(out["resumo"], "x")

    def test_garbage_raises(self):
        with self.assertRaises(ValueError):
            parse("não sei")
        with self.assertRaises(ValueError):
            parse("{quebrado")


class InjectionTests(unittest.TestCase):
    def test_only_the_sqli_alert_is_flagged(self):
        flagged = {a["rule"]["id"] for a in make_alerts() if looks_like_injection(a)}
        self.assertEqual(flagged, {"31103"})


class ContextTests(unittest.TestCase):
    def test_correlation_appears_only_after_record(self):
        brute, suricata = make_alerts()[:2]
        with tempfile.TemporaryDirectory() as d, ContextDB.create(Path(d) / "c.db") as db:
            self.assertEqual(db.build_context(brute)["correlacao_24h"], [])
            db.record(brute)
            corr = db.build_context(suricata)["correlacao_24h"]
            self.assertEqual([c["regra"] for c in corr], ["5763"])

    def test_asset_and_playbook_lookup(self):
        fim = make_alerts()[4]
        with tempfile.TemporaryDirectory() as d, ContextDB.create(Path(d) / "c.db") as db:
            ctx = db.build_context(fim)
            self.assertEqual(ctx["ativo"]["criticidade"], "critica")
            self.assertEqual(ctx["playbook"]["titulo"], "Mudança em arquivo crítico")
            self.assertNotIn("correlacao_24h", ctx)  # sem IP de origem


if __name__ == "__main__":
    unittest.main()
