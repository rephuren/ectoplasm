"""Экспорт правил в JSON: чтобы шлюз или другой инструмент мог использовать те же признаки. Шаблоны в синтаксисе Python `re`: у JavaScript отличаются встроенные флаги, их нужно переносить отдельно."""
import json

from . import injection, model, sinks, trace


def export() -> dict:
    return {
        "version": 1,
        "sinks": {
            "bash": [{"code": c, "severity": sev, "title": title, "pattern": pat.pattern, "flags": pat.flags & 2 and ["IGNORECASE"] or []} for c, sev, title, pat in sinks.BASH_RULES],
            "secret_paths": sinks.SECRET_PATH.pattern, "config_paths": sinks.CONFIG_PATH.pattern,
            "mcp_write_verbs": sinks.MCP_WRITE.pattern, "mcp_secret_tables": sinks.SECRET_TABLE.pattern, "mcp_trusted_prefixes": list(sinks.MCP_TRUSTED),
            "write_tools": sorted(sinks.WRITE_TOOLS),
        },
        "injection": {"patterns": [{"label": label, "weak": label in injection.WEAK_LABELS, "pattern": pat.pattern} for label, pat in injection.PATTERNS],
                      "hidden_run_min": 8, "hidden_chars": injection.HIDDEN_CHARS, "rule": "связь строится, если есть сильная метка или две разные слабые"},
        "sources": {"untrusted": ["WebFetch", "WebSearch", "mcp__* (кроме серверов клиента)", "Bash с сетевой командой не на localhost", "файлы из git clone/curl -o/wget", "node_modules, site-packages"],
                    "trusted_mcp_prefixes": list(model.TRUSTED_MCP_PREFIXES)},
        "trifecta": {"span_events": trace.TRIFECTA_SPAN, "outward_sinks": sorted(trace.EXFIL_LEG), "rule": "недоверенный текст, затем доступ к данным, затем отправка наружу в одном ходе"},
    }


def render() -> str:
    return json.dumps(export(), ensure_ascii=False, indent=2) + "\n"
