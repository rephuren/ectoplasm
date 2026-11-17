"""Самодостаточный HTML-отчёт: без скриптов, внешних файлов и ссылок, всё экранируется, CSP запрещает всё кроме встроенных стилей."""
import html

from .mask import mask
from .model import UNTRUSTED_MIN

CSS = (
    ":root{--bg:#050505;--panel:#0b0b0b;--line:#1c1c1c;--text:#e8e8e8;--dim:#8a8a8a;--red:#b3000f;--hot:#ff2a3d}"
    "*{box-sizing:border-box}html{background:var(--bg)}body{margin:0 auto;max-width:1000px;padding:28px 16px 60px;color:var(--text);background:var(--bg);"
    'font:14px/1.55 "SF Mono",Menlo,Consolas,monospace}'
    "h1{font-size:26px;margin:0 0 2px;letter-spacing:.02em}h1::before{content:'▓ ';color:var(--red)}"
    ".meta{color:var(--dim);margin:0 0 22px;overflow-wrap:anywhere}"
    ".stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:0 0 26px}"
    ".stat{background:var(--panel);border:1px solid var(--line);padding:10px 12px}.stat b{display:block;font-size:24px;font-weight:600}"
    ".stat span{color:var(--dim);font-size:12px}.stat.hot b{color:var(--hot)}"
    "h2{font-size:13px;font-weight:400;color:var(--dim);text-transform:uppercase;letter-spacing:.14em;margin:30px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}"
    ".tl{display:flex;flex-wrap:wrap;gap:2px;margin:0 0 6px}"
    ".tl i{display:block;flex:1 1 7px;max-width:34px;min-width:5px;height:16px;background:#1c1c1c}"
    ".tl i.k-user{background:#e8e8e8;height:22px}.tl i.k-assistant{background:#3a3a3a}.tl i.k-call{background:#5a5a5a}"
    ".tl i.k-result{background:#2a2a2a}.tl i.u{background:#8a6a00}.tl i.src{background:#d4a017;height:22px}"
    ".tl i.sink{background:var(--red);height:26px}.tl i.sink.crit{background:var(--hot)}"
    ".legend{color:var(--dim);font-size:12px;display:flex;gap:16px;flex-wrap:wrap;margin:0 0 4px}.legend b{display:inline-block;width:10px;height:10px;margin-right:6px;vertical-align:-1px}"
    ".inc{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--red);padding:14px 16px;margin:0 0 14px}"
    ".inc.critical{border-left-color:var(--hot)}.inc.medium,.inc.low{border-left-color:#8a8a8a}"
    ".top{display:flex;gap:10px;flex-wrap:wrap;align-items:baseline;margin:0 0 6px}"
    ".sev{color:var(--hot);font-weight:600}.inc.medium .sev,.inc.low .sev{color:var(--text)}"
    ".tag{border:1px solid var(--line);padding:0 8px;color:var(--dim);font-size:12px}.tag.strong{color:var(--hot);border-color:var(--red)}"
    "code{display:block;white-space:pre-wrap;overflow-wrap:anywhere;background:#000;border:1px solid var(--line);padding:8px 10px;margin:6px 0 10px}"
    ".link{margin:8px 0 0;padding-left:12px;border-left:1px solid var(--line)}.link small{color:var(--dim)}"
    "blockquote{margin:4px 0 0;color:var(--dim);overflow-wrap:anywhere}blockquote::before{content:'« '}blockquote::after{content:' »'}"
    ".none{color:var(--dim);padding:16px;border:1px dashed var(--line)}"
    "footer{color:var(--dim);font-size:12px;margin-top:34px;border-top:1px solid var(--line);padding-top:12px}"
)
CSP = "default-src 'none'; style-src 'unsafe-inline'"
SEV = {"critical": "критично", "high": "высокий", "medium": "средний", "low": "низкий"}
CONF = {"strong": "связь сильная", "medium": "связь средняя", "weak": "связь слабая"}
KIND_LABEL = {"provenance": "происхождение адреса", "path": "происхождение пути", "instruction": "похоже на инструкцию", "proximity": "близость по времени"}
MAX_CELLS = 4000


def _timeline(session, incidents) -> tuple[str, int]:
    sinks = {i.sink_idx: i for i in incidents}
    sources = {link.source_idx for i in incidents for link in i.links if link.kind != "proximity"}
    events = session.events
    step = max(1, -(-len(events) // MAX_CELLS))
    cells = []
    for start in range(0, len(events), step):
        chunk = events[start:start + step]
        cls = []
        title = f"#{chunk[0].idx}" + (f"–#{chunk[-1].idx}" if len(chunk) > 1 else "")
        top = max(chunk, key=lambda e: (e.idx in sinks, e.idx in sources, e.kind == "user", e.rank))
        cls.append(f"k-{top.kind}")
        if top.kind == "result" and top.rank >= UNTRUSTED_MIN:
            cls.append("u")
        if any(e.idx in sources for e in chunk):
            cls.append("src")
        hit = [sinks[e.idx] for e in chunk if e.idx in sinks]
        if hit:
            cls.append("sink")
            if any(h.severity == "critical" for h in hit):
                cls.append("crit")
        title += f" {top.kind}" + (f" {top.tool}" if top.tool else "")
        cells.append(f'<i class="{" ".join(cls)}" title="{html.escape(title)}"></i>')
    return "".join(cells), step


def render(session, incidents, shown_floor: str = "medium", hidden=()) -> str:
    e = html.escape
    events = session.events
    untrusted = sum(1 for ev in events if ev.kind == "result" and ev.rank >= UNTRUSTED_MIN)
    strong = sum(1 for i in incidents if i.confidence == "strong")
    cells, step = _timeline(session, incidents)
    cards = []
    for inc in incidents:
        top = max(inc.sinks, key=lambda s: s.rank)
        links = "".join(
            f'<div class="link">{e(link.source_label)} · <small>{e(KIND_LABEL.get(link.kind, link.kind))}</small><br>{e(link.note)}'
            + (f"<blockquote>{e(link.evidence)}</blockquote>" if link.evidence else "") + "</div>"
            for link in inc.links)
        user = '<div class="link"><small>адреса в команде названы пользователем</small></div>' if inc.user_driven else ""
        cards.append(
            f'<div class="inc {e(inc.severity)}"><div class="top"><span class="sev">{e(SEV[inc.severity])}</span><b>{e(inc.sink_label)}</b>'
            f'<span>{e(top.title)}</span><span class="tag {"strong" if inc.confidence == "strong" else ""}">{e(CONF[inc.confidence])}</span></div>'
            f"<code>{e(mask(top.detail)[:600])}</code>{links}{user}</div>")
    for h in hidden:
        cards.insert(0, f'<div class="inc critical"><div class="top"><span class="sev">скрытый текст</span><b>{e(h.source_label)}</b>'
                        f'<span>невидимые символы Unicode: модель их читает, глаза нет</span></div><code>{e(h.decoded or "расшифровать как ASCII не удалось")}</code></div>')
    body = "".join(cards) or '<div class="none">Опасных действий со связью с недоверенным текстом не найдено.</div>'
    scale = f" (одна клетка = {step} событий)" if step > 1 else ""
    return (
        f'<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>seance: {e(session.path.rsplit("/", 1)[-1])}</title>'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}"><style>{CSS}</style></head><body>'
        f'<h1>seance</h1><p class="meta">{e(session.path)}</p>'
        '<div class="stats">'
        f'<div class="stat"><b>{len(events)}</b><span>событий в журнале</span></div>'
        f'<div class="stat"><b>{untrusted}</b><span>недоверенных результатов</span></div>'
        f'<div class="stat {"hot" if incidents else ""}"><b>{len(incidents)}</b><span>опасных действий со связью (≥ {e(shown_floor)})</span></div>'
        f'<div class="stat {"hot" if strong else ""}"><b>{strong}</b><span>сильных связей</span></div>'
        + (f'<div class="stat hot"><b>{len(hidden)}</b><span>мест со скрытым текстом</span></div>' if hidden else "") + "</div>"
        f"<h2>Ход сессии{e(scale)}</h2>"
        '<div class="legend"><span><b style="background:#e8e8e8"></b>сообщение пользователя</span><span><b style="background:#8a6a00"></b>недоверенный результат</span>'
        '<span><b style="background:#d4a017"></b>источник связи</span><span><b style="background:#b3000f"></b>опасное действие</span></div>'
        f'<div class="tl">{cells}</div>'
        f"<h2>Находки</h2>{body}"
        "<footer>Связь означает происхождение данных и признаки инструкции, но не доказывает причину: журнал не показывает, что решила модель. "
        "Отчёт собран локально, скриптов и внешних запросов в нём нет.</footer></body></html>\n"
    )
