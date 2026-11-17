"""Разбор журнала сессии Claude Code (jsonl): остаются только реплики и вызовы инструментов, шум клиента отбрасывается."""
import json

from .model import RANK_LOCAL, RANK_UNTRUSTED, RANK_USER, Event, Session, classify_source
from .sinks import command_of
from .taint import Taint

MAX_TEXT = 200_000  # на один результат: гигантские выводы не нужны для поиска связей
SYSTEM_PREFIXES = ("<system-reminder>", "<command-name>", "<local-command", "<task-notification", "<ide_", "<pasted_content")


def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, str):
                parts.append(b)
            elif isinstance(b, dict) and b.get("type") == "text":
                parts.append(str(b.get("text", "")))
        return "\n".join(parts)
    return ""


def load(path) -> Session:
    session = Session(path=str(path))
    calls: dict[str, Event] = {}
    taint = Taint()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                session.skipped_lines += 1
                continue
            if not isinstance(obj, dict) or obj.get("type") not in ("user", "assistant"):
                continue
            msg = obj.get("message")
            if not isinstance(msg, dict):
                continue
            ts = obj.get("timestamp")
            side = bool(obj.get("isSidechain"))
            cwd = str(obj.get("cwd") or "")
            content = msg.get("content")
            if obj["type"] == "assistant":
                for b in content if isinstance(content, list) else []:
                    if not isinstance(b, dict):
                        continue
                    if b.get("type") == "text" and b.get("text"):
                        session.events.append(Event(len(session.events), "assistant", str(b["text"])[:MAX_TEXT], ts, sidechain=side))
                    elif b.get("type") == "tool_use":
                        raw = b.get("input")
                        inp: dict = raw if isinstance(raw, dict) else {}
                        ev = Event(len(session.events), "call", json.dumps(inp, ensure_ascii=False)[:MAX_TEXT], ts, tool=str(b.get("name")),
                                   call_id=b.get("id"), input=inp, sidechain=side, cwd=cwd)
                        session.events.append(ev)
                        taint.observe(ev.tool or "", command_of(inp), cwd)
                        if ev.call_id:
                            calls[ev.call_id] = ev
                continue
            blocks = content if isinstance(content, list) else [{"type": "text", "text": content}] if isinstance(content, str) else []
            for b in blocks:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_result":
                    call = calls.get(str(b.get("tool_use_id")))
                    tool = call.tool if call else None
                    source, rank = classify_source(tool, call.input if call is not None else {})
                    if call is not None and rank <= RANK_LOCAL and taint.result_is_foreign(tool or "", call.input, command_of(call.input), call.cwd or cwd):
                        source, rank = "clone", RANK_UNTRUSTED
                    session.events.append(Event(len(session.events), "result", _text_of(b.get("content"))[:MAX_TEXT], ts, tool=tool,
                                                call_id=b.get("tool_use_id"), source=source, rank=rank, sidechain=side))
                elif b.get("type") == "text" and b.get("text"):
                    text = str(b["text"])
                    kind = "context" if obj.get("isMeta") or text.lstrip().startswith(SYSTEM_PREFIXES) else "user"
                    session.events.append(Event(len(session.events), kind, text[:MAX_TEXT], ts, rank=RANK_USER, sidechain=side))
    return session
