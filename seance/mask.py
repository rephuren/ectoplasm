"""Маскирование секретов в том, что попадает в отчёт: журнал сессии сам может содержать ключи."""
import re

SECRET_PATTERNS = [
    re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9]{20,}|xox[abp]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"\b[A-Fa-f0-9]{40,}\b"),
]


def mask(text: str) -> str:
    for pat in SECRET_PATTERNS:
        text = pat.sub("«секрет скрыт»", text)
    return text


def snippet(text: str, start: int, end: int, pad: int = 60) -> str:
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    out = re.sub(r"\s+", " ", text[lo:hi]).strip()
    return ("…" if lo else "") + mask(out) + ("…" if hi < len(text) else "")
