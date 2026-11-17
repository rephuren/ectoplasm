import re
from dataclasses import dataclass, field

# риск источника: чем выше, тем меньше ему доверяют
RANK_USER, RANK_LOCAL, RANK_UNTRUSTED = 0, 1, 3
UNTRUSTED_MIN = RANK_UNTRUSTED

BROWSER_HINTS = ("browser", "chrome", "playwright", "puppeteer", "fetch", "search", "web", "http", "scrape", "crawl")
LOCAL_TOOLS = {"Read", "Grep", "Glob", "LS", "NotebookRead", "TodoWrite", "ToolSearch", "Skill"}
WEB_TOOLS = {"WebFetch", "WebSearch"}
NETWORK_CMD = re.compile(r"\b(curl|wget|http|gh\s+(api|pr|issue)|git\s+(clone|fetch|pull)|npm\s+(view|info)|pip\s+download|nslookup|dig)\b")


HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n.*?\n\s*\2\b", re.S)


def _strip_heredocs(cmd: str) -> str:
    return HEREDOC.sub("<<HEREDOC", cmd)


@dataclass
class Event:
    idx: int
    kind: str  # user | context | assistant | call | result
    text: str
    ts: str | None = None
    tool: str | None = None
    call_id: str | None = None
    input: dict = field(default_factory=dict)
    source: str | None = None  # для result: web | mcp | shell | local
    rank: int = RANK_USER
    sidechain: bool = False

    def label(self) -> str:
        return f"#{self.idx} {self.tool}" if self.tool else f"#{self.idx} {self.kind}"


@dataclass
class Session:
    path: str
    events: list = field(default_factory=list)
    skipped_lines: int = 0


def classify_source(tool: str | None, call_input: dict) -> tuple[str, int]:
    """Откуда пришёл результат инструмента и насколько ему доверять."""
    name = tool or ""
    if name in WEB_TOOLS:
        return "web", RANK_UNTRUSTED
    if name in LOCAL_TOOLS:
        return "local", RANK_LOCAL
    if name == "Bash":
        cmd = str(call_input.get("command", ""))
        return ("shell", RANK_UNTRUSTED) if NETWORK_CMD.search(_strip_heredocs(cmd)) else ("shell", RANK_LOCAL)
    if name.startswith("mcp__"):
        low = name.lower()
        if any(h in low for h in BROWSER_HINTS):
            return "web", RANK_UNTRUSTED
        return "mcp", RANK_UNTRUSTED
    return "other", RANK_LOCAL
