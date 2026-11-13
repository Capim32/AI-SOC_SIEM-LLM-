# soc_triage

Triagem de alertas Wazuh com LLM local (Ollama) + Context BD em SQLite.

    python3 -m soc_triage all --dry-run          # monta os prompts, sem LLM
    python3 -m soc_triage all --model qwen2.5:3b # gera alertas, cria BD, chama o Ollama
    python3 -m soc_triage run                    # reprocessa mantendo BD e alertas
    python3 -m unittest discover -s tests -t .   # testes

Saída em lab_out/: alerts.ndjson, context.db, report_*.md e report_*.jsonl.
