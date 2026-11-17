"""Признаки инструкции, адресованной модели, внутри недоверенного текста (веб-страница, ответ MCP, вывод сети)."""
import re
from dataclasses import dataclass

PATTERNS = [
    ("игнорировать прежние указания", re.compile(r"(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|system)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|messages?)\b")),
    ("игнорировать прежние указания", re.compile(r"(?i)(игнорируй|забудь|отмени)[^.\n]{0,40}(предыдущ|прежн|выше|систем)[^.\n]{0,30}(инструкц|указани|правил|промпт)")),
    ("скрыть от пользователя", re.compile(r"(?i)\b(do not|don't|never)\b[^.\n]{0,25}\b(tell|inform|mention|show|reveal)\b[^.\n]{0,25}\b(the )?user\b")),
    ("скрыть от пользователя", re.compile(r"(?i)(не\s+(говори|сообщай|показывай|упоминай))[^.\n]{0,30}пользовател")),
    ("обращение к модели", re.compile(r"(?i)(<\s*important\s*>|\[\s*system\s*\]|\bas an? (ai|assistant|llm)\b|\bnote to (the )?(ai|assistant|agent)\b|\bwhen you (read|see) this\b)")),
    ("приказ выполнить", re.compile(r"(?i)\b(you must|you should now|now you (must|should|will)|first,? (run|execute|call|send|read))\b[^.\n]{0,60}\b(run|execute|call|send|read|fetch|curl|upload|post|write|append|install)\b")),
    ("приказ выполнить", re.compile(r"(?i)(ты должен|теперь (ты )?(выполни|запусти|отправь|прочитай))")),
    ("загрузка и запуск", re.compile(r"(?i)\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b")),
    ("отправка секретов", re.compile(r"(?i)\b(send|post|upload|exfiltrate|forward|curl)\b[^.\n]{0,80}\b(\.env|id_rsa|credentials|api[_ -]?keys?|secrets?|tokens?|passwords?|ssh key)\b")),
]
HIDDEN_CHARS = "\U000e0000-\U000e007f\u2060-\u2064\u202a-\u202e\u2066-\u2069"
INVISIBLE_RUN = re.compile("[" + HIDDEN_CHARS + "]{8,}")  # короткие последовательности бывают в флагах-эмодзи, скрытый текст длиннее


WEAK_LABELS = {"приказ выполнить"}  # встречается в обычных инструкциях («сначала выполните npm install»): сама по себе не повод


@dataclass
class Hit:
    label: str
    start: int
    end: int
    decoded: str = ""


def find(text: str) -> list[Hit]:
    hits = [Hit(label, m.start(), m.end()) for label, pat in PATTERNS for m in pat.finditer(text)]
    for m in INVISIBLE_RUN.finditer(text):
        decoded = "".join(chr(ord(ch) - 0xE0000) for ch in m.group() if 0xE0020 <= ord(ch) <= 0xE007E)
        hits.append(Hit("невидимые символы", m.start(), m.end(), decoded))
    hits.sort(key=lambda h: h.start)
    return hits


def convincing(hits: list[Hit]) -> list[Hit]:
    """Находки, на которые можно опираться: есть сильный признак или сошлись минимум два разных."""
    if any(h.label not in WEAK_LABELS for h in hits) or len({h.label for h in hits}) >= 2:
        return hits
    return []
