"""SARIF 2.1.0: находки ectoplasm для вкладки Security на GitHub и других просмотрщиков."""
import json
from importlib import metadata

from .mask import mask

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _version() -> str:
    try:
        return metadata.version("ectoplasm")
    except metadata.PackageNotFoundError:
        return "unknown"


def build(sessions) -> dict:
    """sessions: список (session, incidents, hidden)."""
    rules: dict[str, dict] = {}
    results = []

    def rule(rule_id: str, title: str, severity: str) -> int:
        if rule_id not in rules:
            rules[rule_id] = {"id": rule_id, "name": rule_id, "shortDescription": {"text": title}, "defaultConfiguration": {"level": LEVEL[severity]},
                              "properties": {"tags": ["security", "agent", "prompt-injection"], "security-severity": SECURITY_SEVERITY[severity]}}
        return list(rules).index(rule_id)

    for session, incidents, hidden in sessions:
        uri = session.path.replace("\\", "/")
        for inc in incidents:
            top = max(inc.sinks, key=lambda s: s.rank)
            link = "; ".join(f"{lk.source_label}: {lk.note}" for lk in inc.links if lk.kind != "proximity")[:600]
            results.append({
                "ruleId": top.code, "ruleIndex": rule(top.code, top.title, inc.severity), "level": LEVEL[inc.severity],
                "message": {"text": f"{inc.sink_label}: {top.title}. Связь {inc.confidence}. {link} Действие: {mask(top.detail)[:300]}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}, "logicalLocations": [{"name": f"event #{inc.sink_idx}"}]}],
                "properties": {"confidence": inc.confidence, "event": inc.sink_idx, "userDriven": inc.user_driven},
            })
        for h in hidden:
            results.append({
                "ruleId": "hidden-text", "ruleIndex": rule("hidden-text", "Скрытый текст Unicode в прочитанном агентом", "high"), "level": "error",
                "message": {"text": f"{h.source_label}: скрытый текст «{mask(h.decoded)[:200]}»"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}, "logicalLocations": [{"name": f"event #{h.event_idx}"}]}],
            })
    return {"$schema": SCHEMA, "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "ectoplasm", "version": _version(), "rules": list(rules.values())}}, "results": results}]}


def render(sessions) -> str:
    return json.dumps(build(sessions), ensure_ascii=False, indent=2) + "\n"
