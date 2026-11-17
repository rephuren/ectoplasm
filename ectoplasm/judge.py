"""Внешний судья для перефразированных инструкций: ваша команда читает текст из stdin и печатает JSON {"injection": true|false}.
Текст уходит в эту команду целиком (до 4000 символов), поэтому судью выбираете и отвечаете за него вы. В пакете модели нет."""
import json
import shlex
import subprocess
import sys

MAX_TEXT = 4000


def command_judge(command: str, timeout: float = 20.0):
    argv = shlex.split(command)
    cache: dict[str, bool | None] = {}

    def judge(text: str) -> bool | None:
        key = text[:MAX_TEXT]
        if key in cache:
            return cache[key]
        verdict: bool | None = None
        try:
            done = subprocess.run(argv, input=key, capture_output=True, text=True, timeout=timeout, check=False)
            data = json.loads(done.stdout.strip().splitlines()[-1]) if done.stdout.strip() else {}
            if isinstance(data, dict) and isinstance(data.get("injection"), bool):
                verdict = data["injection"]
            else:
                print("судья: ответ без поля injection, результат пропущен", file=sys.stderr)
        except (OSError, ValueError, subprocess.TimeoutExpired, IndexError) as e:
            print(f"судья недоступен: {e.__class__.__name__}", file=sys.stderr)
        cache[key] = verdict
        return verdict

    return judge
