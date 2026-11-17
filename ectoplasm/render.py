import json

from .mask import mask

LABEL = {"critical": "критично", "high": "высокий", "medium": "средний", "low": "низкий"}
MARK = {"critical": "▓▓", "high": "▓", "medium": "▒", "low": "░"}
CONF = {"strong": "сильная", "medium": "средняя", "weak": "слабая"}
RED, DIM, BOLD, RESET = "\033[38;2;179;0;15m", "\033[2m", "\033[1m", "\033[0m"


def text(session, incidents, color: bool, hidden=()) -> str:
    def c(code, s):
        return f"{code}{s}{RESET}" if color and code else s

    out = [c(BOLD, "ectoplasm") + c(DIM, f"  {session.path}  (событий {len(session.events)})")]
    if not incidents:
        out += ["", "  опасных действий со связью с недоверенным текстом не найдено"]
    for inc in incidents:
        hot = inc.severity in ("critical", "high")
        top = max(inc.sinks, key=lambda s: s.rank)
        out.append("")
        head = f"{c(RED if hot else '', MARK[inc.severity])} {c(RED + BOLD if hot else BOLD, LABEL[inc.severity].ljust(8))}"
        out.append(f"{head} {inc.sink_label}  {top.title}  {c(DIM, '[связь: ' + CONF[inc.confidence] + ']')}")
        out.append(f"     {mask(top.detail)[:160]}")
        if inc.user_driven:
            out.append(c(DIM, "     адреса в команде есть в сообщениях пользователя"))
        for link in inc.links:
            out.append(f"     ↳ {link.source_label}: {link.note}")
            if link.evidence:
                out.append(c(DIM, f"       «{link.evidence}»"))
    for h in hidden:
        out.append("")
        out.append(f"{c(RED, '▓')} {c(RED + BOLD, 'скрытый текст')} {h.source_label}  {c(DIM, 'невидимые символы Unicode, которые модель читает, а глаза нет')}")
        out.append(f"     расшифровка: «{h.decoded or 'не ASCII, но символы скрытые'}»")
    n_strong = sum(1 for i in incidents if i.confidence == "strong")
    out += ["", c(DIM, f"находок: {len(incidents)}, сильных: {n_strong}.  Связь означает происхождение данных и признаки инструкции, но не доказывает причину.")]
    return "\n".join(out) + "\n"


def as_json(session, incidents, hidden=()) -> str:
    return json.dumps({
        "session": session.path, "events": len(session.events), "skipped_lines": session.skipped_lines,
        "hidden_text": [{"event": h.event_idx, "source": h.source_label, "decoded": h.decoded} for h in hidden],
        "incidents": [{
            "event": i.sink_idx, "tool": i.sink_label, "severity": i.severity, "confidence": i.confidence, "user_driven": i.user_driven,
            "sinks": [{"code": s.code, "severity": s.severity, "title": s.title, "detail": mask(s.detail)[:500]} for s in i.sinks],
            "links": [{"kind": link.kind, "source_event": link.source_idx, "source": link.source_label, "note": link.note, "evidence": link.evidence} for link in i.links],
        } for i in incidents],
    }, ensure_ascii=False, indent=2) + "\n"
