"""Разбор многих журналов: параллельно и с кэшем. Результат на файл это небольшой словарь, поэтому кэш и передача между процессами дёшевы."""
import hashlib
import json
import os
import re
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from . import trace, transcript

VERSION = "3"  # менять при любых изменениях правил: старый кэш становится недействительным
SOURCE_TOOL = re.compile(r"^#\d+\s+(\S+)")


def cache_dir() -> Path:
    base = os.environ.get("ECTOPLASM_CACHE") or os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "ectoplasm")
    return Path(base)


def summarize_file(path: str, min_confidence: str = "weak", fmt: str = "auto") -> dict:
    """Все находки файла с уровнем связи не ниже weak: фильтр по уровню применяется уже при сборке сводки."""
    session = transcript.load(path, fmt=fmt)
    incidents = []
    for inc in trace.report(session, min_confidence):
        sources = [m.group(1) for lk in inc.links if lk.kind != "proximity" and (m := SOURCE_TOOL.match(lk.source_label))]
        incidents.append({"code": max(inc.sinks, key=lambda s: s.rank).code, "severity": inc.severity, "confidence": inc.confidence, "sources": sources})
    first = next((e.ts for e in session.events if e.ts), None)
    return {"path": str(path), "events": len(session.events), "incidents": incidents, "hidden": len(trace.hidden_text(session)), "day": first[:10] if first else None}


def _key(path: str, min_confidence: str, fmt: str) -> list:
    st = os.stat(path)
    return [st.st_mtime_ns, st.st_size, VERSION, min_confidence, fmt]


def _cached(path: str, min_confidence: str, fmt: str, use_cache: bool) -> dict:
    slot = cache_dir() / (hashlib.sha1(os.path.abspath(path).encode()).hexdigest() + ".json")
    key = _key(path, min_confidence, fmt)
    if use_cache:
        try:
            saved = json.loads(slot.read_text(encoding="utf-8"))
            if saved.get("key") == key:
                return saved["data"]
        except (OSError, ValueError, KeyError):
            pass
    data = summarize_file(path, min_confidence, fmt)
    if use_cache:
        try:
            slot.parent.mkdir(parents=True, exist_ok=True)
            slot.write_text(json.dumps({"key": key, "data": data}, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass  # кэш необязателен: нет прав на запись, значит считаем каждый раз
    return data


def _one(args: tuple) -> dict | None:
    path, min_confidence, fmt, use_cache = args
    try:
        return _cached(path, min_confidence, fmt, use_cache)
    except OSError:
        return None


def analyze_many(files, min_confidence: str = "weak", fmt: str = "auto", jobs: int = 1, use_cache: bool = True) -> list[dict]:
    work = [(str(f), min_confidence, fmt, use_cache) for f in files]
    if jobs > 1 and len(work) > 1:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(_one, work, chunksize=1))
    else:
        results = [_one(w) for w in work]
    return [r for r in results if r is not None]
