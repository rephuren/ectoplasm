"""Разбор журнала сессии Claude Code (jsonl): остаются только реплики и вызовы инструментов, шум клиента отбрасывается."""
import contextlib
import json
import os

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


@contextlib.contextmanager
def _open(path, tail_bytes: int | None):
    """Строки журнала; при tail_bytes только хвост файла, начиная с целой строки (нужно хуку: ход обычно короткий, а файл бывает в десятки мегабайт)."""
    with open(path, "rb") as raw:
        size = os.fstat(raw.fileno()).st_size
        if tail_bytes and size > tail_bytes:
            raw.seek(size - tail_bytes)
            raw.readline()
        yield (chunk.decode("utf-8", errors="replace") for chunk in raw)


class Builder:
    """Общая сборка событий: на нём построены читатели разных форматов, чтобы правила не зависели от формата журнала."""

    def __init__(self, path: str):
        self.session = Session(path=path)
        self.calls: dict[str, Event] = {}
        self.taint = Taint()

    def _next(self) -> int:
        return len(self.session.events)

    def user(self, text: str, ts=None, cwd: str = "", side: bool = False, context: bool = False) -> None:
        kind = "context" if context or text.lstrip().startswith(SYSTEM_PREFIXES) else "user"
        self.session.events.append(Event(self._next(), kind, text[:MAX_TEXT], ts, rank=RANK_USER, sidechain=side, cwd=cwd))

    def assistant(self, text: str, ts=None, side: bool = False) -> None:
        self.session.events.append(Event(self._next(), "assistant", text[:MAX_TEXT], ts, sidechain=side))

    def call(self, tool: str, inp: dict, call_id=None, ts=None, cwd: str = "", side: bool = False) -> None:
        ev = Event(self._next(), "call", json.dumps(inp, ensure_ascii=False)[:MAX_TEXT], ts, tool=tool, call_id=call_id, input=inp, sidechain=side, cwd=cwd)
        self.session.events.append(ev)
        self.taint.observe(tool, command_of(inp), cwd)
        if call_id:
            self.calls[str(call_id)] = ev

    def result(self, call_id, text: str, ts=None, cwd: str = "", side: bool = False) -> None:
        call = self.calls.get(str(call_id))
        tool = call.tool if call else None
        source, rank = classify_source(tool, call.input if call is not None else {})
        if call is not None and rank <= RANK_LOCAL and self.taint.result_is_foreign(tool or "", call.input, command_of(call.input), call.cwd or cwd):
            source, rank = "clone", RANK_UNTRUSTED
        self.session.events.append(Event(self._next(), "result", text[:MAX_TEXT], ts, tool=tool, call_id=None if call_id is None else str(call_id), source=source, rank=rank, sidechain=side))


def _json_lines(fh, session: Session):
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            session.skipped_lines += 1
            continue
        if isinstance(obj, dict):
            yield obj


def _claude(path, tail_bytes) -> Session:
    b = Builder(str(path))
    with _open(path, tail_bytes) as fh:
        for obj in _json_lines(fh, b.session):
            if obj.get("type") not in ("user", "assistant"):
                continue
            msg = obj.get("message")
            if not isinstance(msg, dict):
                continue
            ts, side, cwd, content = obj.get("timestamp"), bool(obj.get("isSidechain")), str(obj.get("cwd") or ""), msg.get("content")
            if obj["type"] == "assistant":
                for blk in content if isinstance(content, list) else []:
                    if not isinstance(blk, dict):
                        continue
                    if blk.get("type") == "text" and blk.get("text"):
                        b.assistant(str(blk["text"]), ts, side)
                    elif blk.get("type") == "tool_use":
                        raw = blk.get("input")
                        b.call(str(blk.get("name")), raw if isinstance(raw, dict) else {}, blk.get("id"), ts, cwd, side)
                continue
            blocks = content if isinstance(content, list) else [{"type": "text", "text": content}] if isinstance(content, str) else []
            for blk in blocks:
                if not isinstance(blk, dict):
                    continue
                if blk.get("type") == "tool_result":
                    b.result(blk.get("tool_use_id"), _text_of(blk.get("content")), ts, cwd, side)
                elif blk.get("type") == "text" and blk.get("text"):
                    b.user(str(blk["text"]), ts, cwd, side, context=bool(obj.get("isMeta")))
    return b.session


def _codex_command(args) -> str:
    cmd = args.get("command") if isinstance(args, dict) else None
    if isinstance(cmd, list):
        parts = [str(c) for c in cmd]
        return parts[2] if len(parts) >= 3 and parts[0] in ("bash", "sh", "zsh") and parts[1] in ("-lc", "-c") else " ".join(parts)
    return str(cmd or args.get("cmd", "") if isinstance(args, dict) else "")


def _codex(path, tail_bytes) -> Session:
    """Формат rollout-файлов Codex CLI по описаниям сообщества (официальной спецификации нет, формат меняется между версиями). На реальных файлах не проверялся."""
    b = Builder(str(path))
    with _open(path, tail_bytes) as fh:
        for obj in _json_lines(fh, b.session):
            payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
            if obj.get("type") not in ("response_item", None) and "payload" in obj:
                continue
            kind, ts = payload.get("type"), obj.get("timestamp")
            if kind == "message":
                role, text = payload.get("role"), "\n".join(str(c.get("text", "")) for c in payload.get("content", []) if isinstance(c, dict))
                if text and role == "user":
                    b.user(text, ts)
                elif text and role == "assistant":
                    b.assistant(text, ts)
            elif kind in ("function_call", "custom_tool_call", "local_shell_call"):
                name = str(payload.get("name") or "shell")
                raw = payload.get("arguments") or payload.get("input") or payload.get("action") or {}
                try:
                    args = json.loads(raw) if isinstance(raw, str) else raw
                except json.JSONDecodeError:
                    args = {"raw": raw}
                if not isinstance(args, dict):
                    args = {"raw": args}
                if name in ("shell", "exec_command", "container.exec", "local_shell"):
                    b.call("Bash", {"command": _codex_command(args)}, payload.get("call_id") or payload.get("id"), ts)
                elif name == "apply_patch":
                    patch = str(args.get("input") or args.get("raw") or "")
                    target = next((ln.split(":", 1)[1].strip() for ln in patch.splitlines() if ln.startswith(("*** Update File:", "*** Add File:", "*** Delete File:"))), "")
                    b.call("Edit", {"file_path": target, "patch": patch[:2000]}, payload.get("call_id"), ts)
                else:
                    b.call(name, args, payload.get("call_id"), ts)
            elif kind in ("function_call_output", "custom_tool_call_output"):
                out = payload.get("output")
                if isinstance(out, str):
                    try:
                        data = json.loads(out)
                        out = data.get("output", out) if isinstance(data, dict) else out
                    except json.JSONDecodeError:
                        pass
                b.result(payload.get("call_id"), _text_of(out) if not isinstance(out, str) else out, ts)
    return b.session


def _generic(path, tail_bytes) -> Session:
    """Нейтральный формат ectoplasm (docs/FORMAT.md): по строке JSON на событие, любой агент может его выгружать."""
    b = Builder(str(path))
    with _open(path, tail_bytes) as fh:
        for obj in _json_lines(fh, b.session):
            kind, ts, cwd = obj.get("kind"), obj.get("ts"), str(obj.get("cwd") or "")
            text = str(obj.get("text") or "")
            inp = obj.get("input") if isinstance(obj.get("input"), dict) else {}
            if kind in ("user", "context"):
                b.user(text, ts, cwd, context=kind == "context")
            elif kind == "assistant":
                b.assistant(text, ts)
            elif kind == "call" and obj.get("tool"):
                b.call(str(obj["tool"]), inp, obj.get("call_id"), ts, cwd)
            elif kind == "result":
                b.result(obj.get("call_id"), text, ts, cwd)
    return b.session


FORMATS = ("auto", "claude", "codex", "generic")


def detect(path) -> str:
    """По первым строкам: у Codex есть session_meta/response_item, у универсального формата поле kind, остальное считается журналом Claude Code."""
    try:
        with open(path, "rb") as fh:
            for _, raw in zip(range(40), fh, strict=False):
                try:
                    obj = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(obj, dict):
                    continue
                if obj.get("type") in ("session_meta", "response_item", "turn_context") or ("payload" in obj and "timestamp" in obj and obj.get("type") != "user"):
                    return "codex"
                if obj.get("kind") in ("user", "context", "assistant", "call", "result"):
                    return "generic"
                if obj.get("type") in ("user", "assistant"):
                    return "claude"
    except OSError:
        pass
    return "claude"


def load(path, tail_bytes: int | None = None, fmt: str = "auto") -> Session:
    if fmt == "auto":
        fmt = detect(path)
    return {"claude": _claude, "codex": _codex, "generic": _generic}[fmt](path, tail_bytes)
