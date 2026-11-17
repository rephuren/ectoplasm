"""Какие каталоги и файлы агент получил извне (git clone, curl -o, wget, распаковка), чтобы чтение оттуда считалось недоверенным источником."""
import os
import re
import shlex
from urllib.parse import urlparse

SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\n)\s*")
THIRD_PARTY = re.compile(r"(^|/)(node_modules|site-packages|vendor|third_party|\.venv/lib)(/|$)")
PATHISH = re.compile(r"^[~/.\w$-][^\s]*$")


def _words(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def resolve(path: str, cwd: str) -> str:
    return os.path.normpath(os.path.join(cwd or "/", os.path.expanduser(path)))


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _repo_name(url: str) -> str:
    tail = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1] if "://" in url else url.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return tail[:-4] if tail.endswith(".git") else tail


class Taint:
    def __init__(self) -> None:
        self.prefixes: list[str] = []

    def _add(self, path: str, cwd: str) -> None:
        if path:
            self.prefixes.append(resolve(path, cwd))

    def observe(self, tool: str, command: str, cwd: str) -> None:
        """Вызывается на каждую команду Bash до её результата: запоминает, куда лёг скачанный код."""
        if tool != "Bash":
            return
        here = cwd
        for seg in SEGMENT_SPLIT.split(command):
            w = _words(seg)
            if not w:
                continue
            if w[0] == "cd" and len(w) > 1:
                here = resolve(w[1], here)
                continue
            args = [a for a in w[1:] if not a.startswith("-")]
            if w[0] == "git" and len(w) > 1 and w[1] == "clone" and len(args) >= 2:
                urls = args[1:]
                self._add(urls[1] if len(urls) > 1 else _repo_name(urls[0]), here)
            elif w[0] == "gh" and w[1:3] == ["repo", "clone"] and len(args) >= 3:
                self._add(args[3] if len(args) > 3 else _repo_name(args[2]), here)
            elif w[0] in ("curl", "wget"):
                for i, a in enumerate(w):
                    if a in ("-o", "-O", "--output", "--output-document") and i + 1 < len(w):
                        self._add(w[i + 1], here)
                    elif a.startswith("-o") and len(a) > 2 and a[:2] == "-o":
                        self._add(a[2:], here)
                if w[0] == "wget" and not any(a in ("-O", "--output-document") for a in w):
                    for a in args:
                        if "://" in a:
                            self._add(_repo_name(a) or "index.html", here)
            elif w[0] in ("unzip", "tar") and any(a in w for a in ("-d", "-C")):
                for flag in ("-d", "-C"):
                    if flag in w and w.index(flag) + 1 < len(w):
                        self._add(w[w.index(flag) + 1], here)

    def is_foreign(self, path: str, cwd: str) -> bool:
        full = resolve(path, cwd)
        return bool(THIRD_PARTY.search(full)) or any(_under(full, p) for p in self.prefixes)

    def result_is_foreign(self, tool: str, inp: dict, command: str, cwd: str) -> bool:
        """Результат инструмента пришёл из скачанного или стороннего кода."""
        if tool in ("Read", "Grep", "Glob", "LS"):
            path = str(inp.get("file_path") or inp.get("path") or "")
            return bool(path) and self.is_foreign(path, cwd)
        if tool != "Bash":
            return False
        here = cwd
        for seg in SEGMENT_SPLIT.split(command):
            w = _words(seg)
            if w and w[0] == "cd" and len(w) > 1:
                here = resolve(w[1], here)
                continue
            for a in w[1:]:
                if not a.startswith("-") and PATHISH.match(a) and self.is_foreign(a, here):
                    return True
            if self.prefixes and any(_under(here, p) for p in self.prefixes) and w:
                return True
        return False
