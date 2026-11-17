"""Связывает опасное действие агента с недоверенным текстом, который был перед ним.

Честная граница: это происхождение данных и признаки инструкции, а не доказательство причины. Журнал не показывает, что «думала» модель,
поэтому у каждой связи есть уровень уверенности и видно, на чём он держится."""
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import injection, sinks
from .mask import mask, snippet
from .model import UNTRUSTED_MIN, Session

WINDOW = 8  # сколько последних недоверенных результатов рассматривать для признаков инструкции
URL_RE = sinks.URL_RE
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$|^(?:\d{1,3}\.){3}\d{1,3}$")
NETWORK_SINKS = {"remote-exec", "exfil", "url-exfil", "network-send", "git-push"}
COMMON_HOSTS = {
    "github.com", "raw.githubusercontent.com", "api.github.com", "gist.github.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "www.npmjs.com",
    "npmjs.com", "localhost", "127.0.0.1", "0.0.0.0", "anthropic.com", "docs.anthropic.com", "claude.ai", "docs.python.org", "python.org", "nodejs.org",
    "developer.mozilla.org", "stackoverflow.com", "en.wikipedia.org", "example.com", "example.org", "w3.org", "schemastore.org", "json.schemastore.org",
}
CONFIDENCE = {"strong": 3, "medium": 2, "weak": 1}


@dataclass
class Link:
    kind: str  # provenance | instruction | proximity
    source_idx: int
    source_label: str
    note: str
    evidence: str


@dataclass
class Incident:
    sink_idx: int
    sink_label: str
    sinks: list
    links: list = field(default_factory=list)
    confidence: str = "weak"
    user_driven: bool = False

    @property
    def severity(self) -> str:
        return max(self.sinks, key=lambda s: s.rank).severity


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:  # мусор вроде «http://[» в журнале не должен ронять разбор
        return ""


def _tokens(text: str) -> list[str]:
    found = {u.rstrip(".,;:'\"") for u in URL_RE.findall(text)}
    for u in list(found):
        host = _host(u)
        if host:
            found.add(host)
    found.update(IP_RE.findall(text))
    out = []
    for t in found:
        host = (_host(t) or t.lower()) if t.startswith("http") else t.lower()
        if not HOST_RE.match(host) or host in COMMON_HOSTS or host.endswith((".example.com", ".example.org")):
            continue
        out.append(t)
    return sorted(out)


def analyze(session: Session) -> list[Incident]:
    user_texts: list[str] = []  # всё, что написал пользователь и что пришло из окружения клиента, до текущего места
    untrusted: list = []  # все результаты с рангом «недоверенно»
    turn_start = 0  # с какого места untrusted начался текущий ход: новое сообщение пользователя снимает прежние подозрения
    incidents: list[Incident] = []
    seen_hits: dict[int, list] = {}
    for ev in session.events:
        if ev.kind in ("user", "context"):
            user_texts.append(ev.text.lower())
            if ev.kind == "user":
                turn_start = len(untrusted)
        elif ev.kind == "result" and ev.rank >= UNTRUSTED_MIN:
            untrusted.append(ev)
        elif ev.kind == "call" and ev.tool:
            found = sinks.classify(ev.tool, ev.input)
            if not found:
                continue
            inc = Incident(ev.idx, ev.label(), found)
            if any(x.code in NETWORK_SINKS for x in found):
                _link_provenance(inc, ev, untrusted, user_texts)
            _link_instruction(inc, untrusted[turn_start:], seen_hits)
            if not inc.links and len(untrusted) > turn_start:
                last = untrusted[-1]
                note = "последний недоверенный результат перед действием, связь только по времени"
                inc.links.append(Link("proximity", last.idx, last.label(), note, ""))
            inc.confidence = _confidence(inc)
            incidents.append(inc)
    return incidents


def _link_provenance(inc: Incident, ev, untrusted: list, user_texts: list[str]) -> None:
    toks = _tokens(sinks.effective_text(ev.tool or '', ev.input))
    if not toks:
        return
    driven = [t for t in toks if any(t.lower() in u for u in user_texts)]
    inc.user_driven = len(driven) == len(toks)
    linked_hosts: set[str] = set()
    for tok in sorted(toks, key=lambda t: not t.startswith("http")):  # сначала полные адреса, потом голые хосты
        if tok in driven or (not tok.startswith("http") and tok.lower() in linked_hosts):
            continue
        for res in reversed(untrusted):
            pos = res.text.lower().find(tok.lower())
            if pos >= 0:
                note = f"«{mask(tok)[:120]}» есть в этом результате и не встречается в сообщениях пользователя"
                inc.links.append(Link("provenance", res.idx, res.label(), note, snippet(res.text, pos, pos + len(tok))))
                linked_hosts.add((_host(tok) or tok).lower())
                break


def _link_instruction(inc: Incident, untrusted: list, cache: dict) -> None:
    for res in untrusted[-WINDOW:]:
        hits = cache.get(res.idx)
        if hits is None:
            hits = cache[res.idx] = injection.find(res.text)
        if hits:
            h = hits[0]
            evidence = f"скрытый текст: {mask(h.decoded)}" if h.decoded else snippet(res.text, h.start, h.end)
            inc.links.append(Link("instruction", res.idx, res.label(), f"в результате есть похожее на инструкцию модели: {h.label}", evidence))


def _confidence(inc: Incident) -> str:
    kinds = {link.kind for link in inc.links}
    top = max(s.rank for s in inc.sinks)
    if top < sinks.SEVERITY["medium"]:
        return "weak"  # мелкие действия вроде обычного POST-запроса не поднимаем выше слабой связи
    if "provenance" in kinds:
        return "strong"
    if "instruction" in kinds and top >= sinks.SEVERITY["medium"]:
        return "medium"
    return "weak"


def report(session: Session, min_confidence: str = "medium") -> list[Incident]:
    floor = CONFIDENCE[min_confidence]
    return [i for i in analyze(session) if CONFIDENCE[i.confidence] >= floor]
