"""Опасные действия агента: что считается «стоком» и насколько он серьёзен."""
import re
from dataclasses import dataclass

from .model import _strip_heredocs

SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}

SECRET_BODY = (r"(\.env\b|\.env\.|id_(rsa|ed25519|ecdsa)|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials|\.ssh/|\.pypirc|\.kube/config|\.docker/config\.json|keychain|\.gnupg)")
SECRET_PATH = re.compile(SECRET_BODY, re.I)
CONFIG_BODY = (
    r"(\.bashrc|\.zshrc|\.zprofile|\.bash_profile|\.profile\b|authorized_keys|crontab|LaunchAgents|LaunchDaemons|\.git/hooks/|\.github/workflows/|"
    r"(^|/)CLAUDE\.md|(^|/)AGENTS\.md|\.cursorrules|\.claude/|\.mcp\.json|\.cursor/|\.vscode/(tasks|settings)\.json)")
CONFIG_PATH = re.compile(CONFIG_BODY, re.I)
CONFIG_WRITE_CMD = re.compile(r"(>>?\s*\S*" + CONFIG_BODY + r"|\btee\s+(-a\s+)?\S*" + CONFIG_BODY + r"|\b(cp|mv|ln|sed\s+-i\S*(\s+'')?)\s+[^\n|;&]*" + CONFIG_BODY + r")", re.I)
BASH_RULES = [
    ("remote-exec", "critical", "загрузка из сети и запуск", re.compile(r"\b(curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(ba|z)?sh\s+<\(\s*(curl|wget)|\beval\s+\"?\$\(\s*(curl|wget)")),
    ("persistence", "high", "закрепление в системе", re.compile(r"(?i)(>>?\s*~?/?[\w./-]*(\.bashrc|\.zshrc|\.profile|\.zprofile)|crontab\b|launchctl\s+(load|bootstrap)|LaunchAgents|authorized_keys|\.git/hooks/)")),
    ("secret-read", "high", "чтение секретов", re.compile(r"(?i)\b(cat|less|more|head|tail|cp|base64|xxd|strings|grep|source|printenv|env)\b[^\n|;&]*" + SECRET_BODY + r"|security\s+find-(generic|internet)-password")),
    ("exfil", "high", "отправка файла или вывода наружу", re.compile(r"(?i)\b(curl|wget)\b[^\n]*(\s(-d|--data[\w-]*|-F|--form|-T|--upload-file)[ =]\S*@|--post-file)|\|\s*(curl|wget)\b[^\n]*(-d|--data|-T|--upload-file|-X\s*(POST|PUT))|\b(nc|ncat|netcat)\s+[\w.-]+\s+\d+|\bscp\s+[^\n]*\S+@[\w.-]+:|\brsync\b[^\n]*\S+@[\w.-]+:")),
    ("network-send", "low", "отправка данных запросом", re.compile(r"(?i)\b(curl|wget)\b[^\n]*(\s(-d|--data[\w-]*|-F|--form)[ =]|-X\s*(POST|PUT))")),
    ("git-push", "medium", "публикация изменений", re.compile(r"\bgit\s+push\b|\bgit\s+remote\s+(add|set-url)\b|\bgh\s+(repo\s+(create|edit)|release\s+create|gist\s+create)\b")),
    ("package-install", "medium", "установка пакета", re.compile(r"\b(npm\s+(install|i|add)|pnpm\s+(add|install)|yarn\s+add|pip3?\s+install|uv\s+pip\s+install|cargo\s+install|go\s+install|brew\s+install|gem\s+install)\b")),
    ("destructive", "medium", "удаление данных", re.compile(r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR])\b(?!\s+(\./)?(node_modules|build|dist|\.venv|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|/tmp/)\S*\s*$)|\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f|push\s+[^\n]*--force)|\bmkfs\b|\bdd\s+if=")),
    ("privilege", "medium", "повышение прав", re.compile(r"\bsudo\b|\bchmod\s+(-R\s+)?(777|u\+s|\+s)\b|\bchown\b[^\n]*root")),
    ("obfuscated-exec", "medium", "запуск скрытой команды", re.compile(r"(?i)\bbase64\s+(-d|--decode|-D)\b[^\n]*\|\s*(ba|z)?sh\b|\beval\b\s+[\"'$]|\bpython3?\s+-c\b[^\n]*(exec|eval|b64decode)")),
]
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+")


@dataclass
class Sink:
    code: str
    severity: str
    title: str
    detail: str

    @property
    def rank(self) -> int:
        return SEVERITY[self.severity]


_COMMIT_MSG = re.compile(r"(\bgit\s+commit\b[^\n]*?\s-[a-z]*m\s*)(\"(?:[^\"\\]|\\.)*\"|'[^']*')", re.S)


def command_of(inp: dict) -> str:
    """Команда без тел heredoc и текста сообщений коммита: там лежит код и проза, а не действия."""
    cmd = _strip_heredocs(str(inp.get("command", "")))
    return _COMMIT_MSG.sub(r'\1""', cmd)


def effective_text(tool: str, inp: dict) -> str:
    return command_of(inp) if tool == "Bash" else str(inp)


def _path_of(inp: dict) -> str:
    return str(inp.get("file_path") or inp.get("path") or inp.get("notebook_path") or "")


def classify(tool: str, inp: dict) -> list[Sink]:
    out: list[Sink] = []
    if tool == "Bash":
        cmd = command_of(inp)
        for code, sev, title, pat in BASH_RULES:
            if pat.search(cmd):
                out.append(Sink(code, sev, title, cmd))
        if any(x.code == "exfil" for x in out):
            out = [x for x in out if x.code != "network-send"]
        if CONFIG_WRITE_CMD.search(cmd) and not any(s.code == "persistence" for s in out):
            out.append(Sink("config-write", "high", "правка конфигурации агента или системы", cmd))
    elif tool in WRITE_TOOLS:
        path = _path_of(inp)
        if CONFIG_PATH.search(path):
            out.append(Sink("config-write", "high", "правка конфигурации агента или системы", path))
    elif tool == "Read":
        path = _path_of(inp)
        if SECRET_PATH.search(path):
            out.append(Sink("secret-read", "high", "чтение секретов", path))
    elif tool in ("WebFetch",) or (tool.startswith("mcp__") and ("navigate" in tool.lower() or "fetch" in tool.lower())):
        url = str(inp.get("url", ""))
        if "?" in url and len(url.split("?", 1)[1]) >= 24:
            out.append(Sink("url-exfil", "medium", "запрос с длинными данными в адресе", url))
    return out
