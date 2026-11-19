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
PATH_SINKS = {"secret-read", "config-write", "persistence"}
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


@dataclass
class Hidden:
    """Невидимый текст в чём угодно, что агент прочитал: правила, файлы, страницы. Свой он или чужой, глазами его не видно."""
    event_idx: int
    source_label: str
    decoded: str
    evidence: str


def hidden_text(session: Session) -> list[Hidden]:
    out = []
    for ev in session.events:
        if ev.kind not in ("context", "result"):
            continue
        for hit in injection.find(ev.text):
            if hit.label == "невидимые символы":
                out.append(Hidden(ev.idx, ev.label(), mask(hit.decoded)[:300], snippet(ev.text, hit.start, hit.start)))
    return out


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


READ_VERB = re.compile(r"(?i)(^|_)(get|read|list|search|query|fetch|select|find|describe|show|view|cat|open)(_|$)")
RESOURCE_KEYS = {"repo", "repository", "owner", "table", "path", "channel", "project", "database", "db", "file", "folder", "bucket", "workspace"}
SLASH_NAME = re.compile(r"\b[\w.-]{2,}/[\w.-]{2,}\b")
TRIFECTA_SPAN = 40  # событий между недоверенным текстом и отправкой
EXFIL_LEG = {"exfil", "network-send", "url-exfil", "mcp-write", "git-push", "remote-exec"}


def _resources(inp: dict) -> set[str]:
    """Названия ресурсов, к которым обращается MCP-вызов: репозиторий, таблица, путь, канал."""
    out: set[str] = set()
    for key, val in inp.items():
        if isinstance(val, str):
            if key.lower() in RESOURCE_KEYS and len(val) >= 3:
                out.add(val.lower())
            out.update(m.lower() for m in SLASH_NAME.findall(val) if "://" not in val)
    return out


def analyze(session: Session, judge=None) -> list[Incident]:
    user_texts: list[str] = []  # всё, что написал пользователь и что пришло из окружения клиента, до текущего места
    untrusted: list = []  # все результаты с рангом «недоверенно»
    turn_start = 0  # с какого места untrusted начался текущий ход: новое сообщение пользователя снимает прежние подозрения
    incidents: list[Incident] = []
    seen_hits: dict[int, list] = {}
    access: list[tuple[int, str, str]] = []  # доступ к данным в текущем ходе: (событие, подпись, сила strong|scope)
    for ev in session.events:
        if ev.kind in ("user", "context"):
            user_texts.append(ev.text.lower())
            if ev.kind == "user":
                turn_start = len(untrusted)
                access = []
        elif ev.kind == "result" and ev.rank >= UNTRUSTED_MIN:
            untrusted.append(ev)
        elif ev.kind == "call" and ev.tool:
            found = sinks.classify(ev.tool, ev.input)
            if len(untrusted) > turn_start:
                _note_access(access, ev, found, user_texts)
            if not found:
                continue
            inc = Incident(ev.idx, ev.label(), found)
            turn = untrusted[turn_start:]
            if any(x.code in NETWORK_SINKS for x in found):
                _link_provenance(inc, ev, untrusted, user_texts)
            _link_paths(inc, ev, turn, user_texts)
            _link_packages(inc, ev, turn, user_texts)
            _link_instruction(inc, turn, seen_hits, judge)
            _link_trifecta(inc, found, turn, access, ev.idx)
            if not inc.links and turn:
                last = untrusted[-1]
                note = "последний недоверенный результат перед действием, связь только по времени"
                inc.links.append(Link("proximity", last.idx, last.label(), note, ""))
            inc.confidence = _confidence(inc)
            incidents.append(inc)
    return incidents


def _note_access(access: list, ev, found: list, user_texts: list[str]) -> None:
    """Запоминает, что после недоверенного текста агент получил доступ к данным: чтение секретов или обращение к ресурсу, которого пользователь не называл."""
    if any(x.code == "secret-read" for x in found):
        access.append((ev.idx, ev.label(), "strong"))
        return
    if ev.tool.startswith("mcp__") and not ev.tool.startswith(sinks.MCP_TRUSTED) and READ_VERB.search(ev.tool.rsplit("__", 1)[-1]):
        foreign = [r for r in _resources(ev.input) if not any(r in u or r.split("/")[-1] in u for u in user_texts)]
        if foreign:
            access.append((ev.idx, ev.label(), "scope"))


def _link_trifecta(inc: Incident, found: list, turn: list, access: list, idx: int) -> None:
    """В одном ходе: недоверенный текст, затем доступ к данным, затем отправка наружу. Формулировка текста не важна."""
    if not turn or not any(x.code in EXFIL_LEG for x in found):
        return
    sources = [r for r in turn if r.source in ("web", "mcp", "clone") and idx - r.idx <= TRIFECTA_SPAN]
    if not sources:
        return  # длинные автономные ходы: тройка складывается случайно, если до отправки далеко от текста
    src = sources[0]
    legs = [a for a in access if src.idx < a[0] <= idx]
    if not legs:
        return
    leg = max(legs, key=lambda a: a[2] == "strong")
    kind = "секреты" if leg[2] == "strong" else "ресурс, которого пользователь не называл"
    note = f"в этом ходе недоверенный текст ({src.label()}), затем доступ к данным ({leg[1]}: {kind}), затем отправка наружу"
    inc.links.append(Link("trifecta", src.idx, src.label(), note, "секреты" if leg[2] == "strong" else ""))


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


def _link_paths(inc: Incident, ev, turn_results: list, user_texts: list[str]) -> None:
    """Чувствительный путь (ключи, .env, файлы памяти агента), который назвала недоверенная страница, а пользователь нет."""
    if not any(x.code in PATH_SINKS for x in inc.sinks):
        return
    text = sinks.effective_text(ev.tool or "", ev.input)
    names = {m.group(0).lower().lstrip("/") for pat in (sinks.SECRET_PATH, sinks.CONFIG_PATH) for m in pat.finditer(text)}
    for name in sorted(names):
        if name.endswith("/") or len(name) < 4 or any(name in u for u in user_texts):  # каталоги вроде .claude/ называет любая страница
            continue
        for res in reversed(turn_results):
            pos = res.text.lower().find(name)
            if pos >= 0:
                note = f"путь «{name}» назван в этом результате, а в сообщениях пользователя его нет"
                inc.links.append(Link("path", res.idx, res.label(), note, snippet(res.text, pos, pos + len(name))))
                break


INSTALL_CMD = re.compile(r"\b(?:npm\s+(?:install|i|add)|pnpm\s+(?:add|install)|yarn\s+add|pip3?\s+install|uv\s+pip\s+install|cargo\s+(?:install|add)|gem\s+install)\b([^;&|\n]*)")
PACKAGE_NAME = re.compile(r"^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]{2,}$", re.I)


def _packages(text: str) -> set[str]:
    """Имена пакетов из команд установки: без флагов, адресов и путей, версия после @ или == отбрасывается."""
    names: set[str] = set()
    for m in INSTALL_CMD.finditer(text):
        for tok in m.group(1).split():
            if tok.startswith("-") or "://" in tok or tok.startswith((".", "/", "~")):
                continue
            tok = re.split(r"(?<=.)@(?=[\d^~<>=*]|latest)|[=<>~!]=?", tok, maxsplit=1)[0].strip("'\"")
            if PACKAGE_NAME.match(tok):
                names.add(tok.lower())
    return names


def _link_packages(inc: Incident, ev, turn_results: list, user_texts: list[str]) -> None:
    """Пакет, который установил агент, назван недоверенным текстом, а пользователь его не называл (подсказка вроде «поставь пакет X»)."""
    if not any(x.code == "package-install" for x in inc.sinks):
        return
    for name in sorted(_packages(sinks.effective_text(ev.tool or "", ev.input))):
        if any(name in u for u in user_texts):
            continue
        for res in reversed(turn_results):
            pos = res.text.lower().find(name)
            if pos >= 0:
                note = f"пакет «{name}» назван в этом результате, а в сообщениях пользователя его нет"
                inc.links.append(Link("package", res.idx, res.label(), note, snippet(res.text, pos, pos + len(name))))
                break


def _hits(text: str, judge) -> list:
    hits = injection.convincing(injection.find(text))
    if not hits and judge is not None:
        verdict = judge(text)
        if verdict:
            hits = [injection.Hit("оценка внешним судьёй", 0, min(len(text), 80), "")]
    return hits


def _link_instruction(inc: Incident, untrusted: list, cache: dict, judge=None) -> None:
    for res in untrusted[-WINDOW:]:
        hits = cache.get(res.idx)
        if hits is None:
            hits = cache[res.idx] = _hits(res.text, judge)
        if hits:
            h = hits[0]
            evidence = f"скрытый текст: {mask(h.decoded)}" if h.decoded else snippet(res.text, h.start, h.end)
            inc.links.append(Link("instruction", res.idx, res.label(), f"в результате есть похожее на инструкцию модели: {h.label}", evidence))


def _confidence(inc: Incident) -> str:
    kinds = {link.kind for link in inc.links}
    top = max(s.rank for s in inc.sinks)
    if top < sinks.SEVERITY["medium"]:
        return "weak"  # мелкие действия вроде обычного POST-запроса не поднимаем выше слабой связи
    if "provenance" in kinds or {"package", "instruction"} <= kinds:  # имя пакета из страницы само по себе слабо: так выглядят и обычные инструкции установки
        return "strong"
    if "trifecta" in kinds and (any(a in kinds for a in ("instruction", "path")) or any(link.kind == "trifecta" and link.evidence == "секреты" for link in inc.links)):
        return "medium"
    if "path" in kinds:
        return "medium"
    if "instruction" in kinds and top >= sinks.SEVERITY["medium"]:
        return "medium"
    return "weak"


def report(session: Session, min_confidence: str = "medium", judge=None) -> list[Incident]:
    floor = CONFIDENCE[min_confidence]
    return [i for i in analyze(session, judge) if CONFIDENCE[i.confidence] >= floor]
