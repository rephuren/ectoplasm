"""Хук Claude Code (PreToolUse): перед выполнением действия смотрит хвост журнала и просит подтверждение, если действие связано с недоверенным текстом.

Принципы: хук никогда не отдаёт решение «allow» (чтобы не обойти ваши правила разрешений) и никогда не ломает работу: любая ошибка или непонятный вход значат «молча пропустить»."""
import json
import sys
from pathlib import Path

from . import trace, transcript
from .model import Event

TAIL_BYTES = 4 * 1024 * 1024
CONFIG = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "ectoplasm hook"}]}]}}


def decide(payload: dict, min_confidence: str = "medium", tail_bytes: int = TAIL_BYTES):
    """Возвращает (incident, session) для действия, которое агент только собирается выполнить, или None."""
    if payload.get("hook_event_name") not in (None, "PreToolUse"):
        return None
    tool, inp, path = payload.get("tool_name"), payload.get("tool_input"), payload.get("transcript_path")
    if not isinstance(tool, str) or not isinstance(inp, dict) or not isinstance(path, str) or not Path(path).is_file():
        return None
    session = transcript.load(path, tail_bytes)
    idx = len(session.events)
    session.events.append(Event(idx, "call", json.dumps(inp, ensure_ascii=False), tool=tool, input=inp, cwd=str(payload.get("cwd") or "")))
    floor = trace.CONFIDENCE[min_confidence]
    for inc in trace.analyze(session):
        if inc.sink_idx == idx and trace.CONFIDENCE[inc.confidence] >= floor:
            return inc, session
    return None


def reason(inc) -> str:
    top = max(inc.sinks, key=lambda s: s.rank)
    link = next((lk for lk in inc.links if lk.kind != "proximity"), inc.links[0] if inc.links else None)
    why = f" {link.source_label}: {link.note}." if link else ""
    return f"ectoplasm: {top.title} ({inc.severity}), связь {inc.confidence}.{why} Подтвердите, если это действие вы просили."


def run(stdin, stdout, stderr, mode: str = "ask", min_confidence: str = "medium") -> int:
    try:
        payload = json.load(stdin)
        found = decide(payload, min_confidence) if isinstance(payload, dict) else None
        if not found:
            return 0
        text = reason(found[0])
        if mode == "warn":
            print(text, file=stderr)
            return 0
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny" if mode == "deny" else "ask",
                                           "permissionDecisionReason": text}}, stdout, ensure_ascii=False)
        print(file=stdout)
        return 0
    except Exception as e:  # хук не должен ломать работу агента
        print(f"ectoplasm hook пропущен: {e.__class__.__name__}", file=stderr)
        return 0


def main_stdio(mode: str, min_confidence: str) -> int:
    return run(sys.stdin, sys.stdout, sys.stderr, mode, min_confidence)
