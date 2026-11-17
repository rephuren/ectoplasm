import argparse
import sys
import tempfile
from pathlib import Path

from . import demo, htmlreport, judge, render, trace, transcript


def _scan(args) -> int:
    root = Path(args.path).expanduser()
    files = [root] if root.is_file() else sorted(root.rglob("*.jsonl"))
    rows: list[dict] = []
    for f in files:
        try:
            session = transcript.load(f)
        except OSError as e:
            print(f"{f}: {e}", file=sys.stderr)
            continue
        found = trace.report(session, args.min_confidence)
        rows.append({"path": str(f), "events": len(session.events), "strong": sum(i.confidence == "strong" for i in found),
                     "medium": sum(i.confidence == "medium" for i in found), "weak": sum(i.confidence == "weak" for i in found),
                     "hidden": len(trace.hidden_text(session))})
    rows.sort(key=lambda r: (-r["hidden"], -r["strong"], -r["medium"], r["path"]))
    if args.json:
        import json
        sys.stdout.write(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
    else:
        print(f"{'скрытых':>8} {'сильных':>8} {'средних':>8} {'событий':>8}  журнал")
        for r in rows:
            print(f"{r['hidden']:>8} {r['strong']:>8} {r['medium']:>8} {r['events']:>8}  {r['path']}")
        print(f"\nжурналов: {len(rows)}. Разберите нужный командой: ectoplasm trace <журнал> [--html отчёт.html]")
    return 1 if any(r["strong"] or r["hidden"] for r in rows) else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ectoplasm", description="Разбор сессии ИИ-агента после инцидента")
    sub = parser.add_subparsers(dest="mode", required=True)
    tr = sub.add_parser("trace", help="найти опасные действия и связать их с недоверенным текстом")
    tr.add_argument("session", help="журнал сессии Claude Code (.jsonl)")
    tr.add_argument("--min-confidence", choices=("weak", "medium", "strong"), default="medium", help="порог уверенности связи (по умолчанию medium)")
    tr.add_argument("--json", action="store_true")
    tr.add_argument("--judge-cmd", metavar="КОМАНДА", help="внешний судья: команда читает текст из stdin и печатает JSON {\"injection\": true|false}")
    tr.add_argument("--html", metavar="ФАЙЛ", help="сохранить отчёт в HTML: временная шкала сессии и цепочки")
    tr.add_argument("--no-color", action="store_true")
    sc = sub.add_parser("scan", help="пройтись по папке с журналами и показать, где есть связи")
    sc.add_argument("path", nargs="?", default="~/.claude/projects", help="папка с журналами (по умолчанию ~/.claude/projects)")
    sc.add_argument("--min-confidence", choices=("weak", "medium", "strong"), default="medium")
    sc.add_argument("--json", action="store_true")
    dm = sub.add_parser("demo", help="синтетическая отравленная сессия: записать и разобрать")
    dm.add_argument("--out", metavar="ФАЙЛ", help="сохранить журнал демо в файл")
    dm.add_argument("--html", metavar="ФАЙЛ", help="сохранить отчёт демо в HTML")
    dm.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    if args.mode == "demo":
        path = args.out
        if not path:
            fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
            path = fh.name
            fh.close()
        demo.write(path)
        session = transcript.load(path)
        session.path = "demo (синтетическая сессия)"
        incidents = trace.report(session)
        hidden = trace.hidden_text(session)
        if args.html:
            Path(args.html).write_text(htmlreport.render(session, incidents, hidden=hidden), encoding="utf-8")
            print(f"HTML-отчёт сохранён: {args.html}", file=sys.stderr)
        sys.stdout.write(render.text(session, incidents, sys.stdout.isatty() and not args.no_color, hidden))
        return 0

    if args.mode == "scan":
        return _scan(args)
    try:
        session = transcript.load(args.session)
    except OSError as e:
        print(f"{args.session}: {e}", file=sys.stderr)
        return 2
    judge_fn = judge.command_judge(args.judge_cmd) if args.judge_cmd else None
    incidents = trace.report(session, args.min_confidence, judge_fn)
    hidden = trace.hidden_text(session)
    if args.html:
        Path(args.html).write_text(htmlreport.render(session, incidents, args.min_confidence, hidden), encoding="utf-8")
        print(f"HTML-отчёт сохранён: {args.html}", file=sys.stderr)
    if args.json:
        sys.stdout.write(render.as_json(session, incidents, hidden))
    else:
        sys.stdout.write(render.text(session, incidents, sys.stdout.isatty() and not args.no_color, hidden))
    return 1 if any(i.confidence == "strong" for i in incidents) or hidden else 0


if __name__ == "__main__":
    sys.exit(main())
