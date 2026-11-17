"""Сводка по папке журналов: где чаще всего недоверенный текст связан с опасными действиями."""
import html
import json
import re
from collections import Counter

from . import trace, transcript

SOURCE_TOOL = re.compile(r"^#\d+\s+(\S+)")


def collect(files, min_confidence: str = "medium", loader=transcript.load) -> dict:
    by_sink: Counter = Counter()
    by_source: Counter = Counter()
    by_conf: Counter = Counter()
    by_day: Counter = Counter()
    sessions: list[dict] = []
    hidden_total = 0
    for f in files:
        try:
            session = loader(f)
        except OSError:
            continue
        found = trace.report(session, min_confidence)
        hidden = trace.hidden_text(session)
        hidden_total += len(hidden)
        for inc in found:
            by_conf[inc.confidence] += 1
            by_sink[max(inc.sinks, key=lambda s: s.rank).code] += 1
            for lk in inc.links:
                m = SOURCE_TOOL.match(lk.source_label)
                if lk.kind != "proximity" and m:
                    by_source[m.group(1)] += 1
        first = next((e.ts for e in session.events if e.ts), None)
        if found and first:
            by_day[first[:10]] += len(found)
        sessions.append({"path": str(f), "events": len(session.events), "incidents": len(found), "strong": sum(i.confidence == "strong" for i in found),
                         "hidden": len(hidden)})
    sessions.sort(key=lambda r: (-r["hidden"], -r["strong"], -r["incidents"], r["path"]))
    return {"sessions": len(sessions), "events": sum(s["events"] for s in sessions), "incidents": sum(by_conf.values()), "hidden_text": hidden_total,
            "by_confidence": dict(by_conf), "by_sink": dict(by_sink.most_common()), "by_source_tool": dict(by_source.most_common()),
            "by_day": dict(sorted(by_day.items())), "top_sessions": sessions[:15]}


def text(data: dict) -> str:
    out = [f"журналов {data['sessions']}, событий {data['events']}, находок {data['incidents']}, мест со скрытым текстом {data['hidden_text']}"]
    for title, key in (("по уровню связи", "by_confidence"), ("по действию", "by_sink"), ("по источнику текста (инструмент)", "by_source_tool"), ("по дням", "by_day")):
        out.append(f"\n{title}:")
        out += [f"  {k:<28} {v}" for k, v in data[key].items()] or ["  —"]
    out.append("\nжурналы с находками:")
    out += [f"  скрытых {s['hidden']}  сильных {s['strong']}  всего {s['incidents']}  {s['path']}" for s in data["top_sessions"] if s["incidents"] or s["hidden"]] or ["  —"]
    return "\n".join(out) + "\n"


def as_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def render_html(data: dict) -> str:
    e = html.escape

    def bars(title: str, items: dict) -> str:
        if not items:
            return f"<h2>{e(title)}</h2><p class='none'>нет данных</p>"
        top = max(items.values())
        rows = "".join(f"<div class='row'><span class='k'>{e(str(k))}</span><span class='bar'><i style='width:{max(2, round(100 * v / top))}%'></i></span><b>{v}</b></div>"
                       for k, v in items.items())
        return f"<h2>{e(title)}</h2>{rows}"

    sessions = "".join(f"<tr><td>{s['hidden']}</td><td>{s['strong']}</td><td>{s['incidents']}</td><td class='p'>{e(s['path'])}</td></tr>" for s in data["top_sessions"]
                       if s["incidents"] or s["hidden"]) or "<tr><td colspan='4'>находок нет</td></tr>"
    css = (":root{--bg:#050505;--panel:#0b0b0b;--line:#1c1c1c;--text:#e8e8e8;--dim:#8a8a8a;--red:#b3000f;--hot:#ff2a3d}*{box-sizing:border-box}html{background:var(--bg)}"
           "body{margin:0 auto;max-width:1000px;padding:28px 16px 60px;color:var(--text);background:var(--bg);font:14px/1.55 'SF Mono',Menlo,Consolas,monospace}"
           "h1{font-size:26px;margin:0 0 6px}h1::before{content:'▓ ';color:var(--red)}h2{font-size:13px;font-weight:400;color:var(--dim);text-transform:uppercase;letter-spacing:.14em;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}"
           ".meta{color:var(--dim)}.row{display:grid;grid-template-columns:190px 1fr 46px;gap:10px;align-items:center;margin:4px 0}.k{overflow-wrap:anywhere}.bar{background:var(--panel);border:1px solid var(--line);height:14px}"
           ".bar i{display:block;height:100%;background:var(--red)}b{text-align:right}table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}"
           "th{color:var(--dim);font-weight:400}.p{overflow-wrap:anywhere}.none{color:var(--dim)}@media(max-width:600px){.row{grid-template-columns:110px 1fr 40px}}")
    return (f"<!doctype html><html lang='ru'><head><meta charset='utf-8'><title>ectoplasm: сводка</title><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><style>{css}</style></head><body><h1>ectoplasm</h1>"
            f"<p class='meta'>журналов {data['sessions']} · событий {data['events']} · находок {data['incidents']} · мест со скрытым текстом {data['hidden_text']}</p>"
            + bars("по уровню связи", data["by_confidence"]) + bars("по действию", data["by_sink"]) + bars("по источнику текста", data["by_source_tool"]) + bars("по дням", data["by_day"])
            + f"<h2>журналы с находками</h2><table><tr><th>скрытых</th><th>сильных</th><th>всего</th><th>журнал</th></tr>{sessions}</table></body></html>\n")
