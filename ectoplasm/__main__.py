import argparse
import sys
import tempfile
from pathlib import Path

from . import demo, hook, htmlreport, judge, render, rules, sarif, stats, trace, transcript


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
    tr.add_argument("--sarif", metavar="ФАЙЛ", help="сохранить находки в SARIF 2.1.0 (GitHub code scanning)")
    tr.add_argument("--no-color", action="store_true")
    hk = sub.add_parser("hook", help="хук Claude Code (PreToolUse): спросить подтверждение до выполнения связанного с недоверенным текстом действия")
    hk.add_argument("--mode", dest="hook_mode", choices=("ask", "deny", "warn"), default="ask", help="ask просит подтверждение (по умолчанию), deny запрещает, warn только пишет в stderr")
    hk.add_argument("--min-confidence", choices=("weak", "medium", "strong"), default="medium")
    hk.add_argument("--print-config", action="store_true", help="напечатать фрагмент для settings.json и выйти (файл настроек не меняется)")
    rp = sub.add_parser("report", help="сводка по папке журналов: источники, действия, дни")
    rp.add_argument("path", nargs="?", default="~/.claude/projects")
    rp.add_argument("--min-confidence", choices=("weak", "medium", "strong"), default="medium")
    rp.add_argument("--json", action="store_true")
    rp.add_argument("--html", metavar="ФАЙЛ")
    ru = sub.add_parser("rules", help="правила в JSON для шлюза и других инструментов")
    ru.add_argument("--json", action="store_true", default=True)
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
    if args.mode == "hook":
        if args.print_config:
            import json
            print(json.dumps(hook.CONFIG, indent=2))
            return 0
        return hook.main_stdio(args.hook_mode, args.min_confidence)
    if args.mode == "rules":
        sys.stdout.write(rules.render())
        return 0
    if args.mode == "report":
        root = Path(args.path).expanduser()
        files = [root] if root.is_file() else sorted(root.rglob("*.jsonl"))
        data = stats.collect(files, args.min_confidence)
        if args.html:
            Path(args.html).write_text(stats.render_html(data), encoding="utf-8")
            print(f"HTML-сводка сохранена: {args.html}", file=sys.stderr)
        sys.stdout.write(stats.as_json(data) if args.json else stats.text(data))
        return 0
    try:
        session = transcript.load(args.session)
    except OSError as e:
        print(f"{args.session}: {e}", file=sys.stderr)
        return 2
    judge_fn = judge.command_judge(args.judge_cmd) if args.judge_cmd else None
    incidents = trace.report(session, args.min_confidence, judge_fn)
    hidden = trace.hidden_text(session)
    if args.sarif:
        Path(args.sarif).write_text(sarif.render([(session, incidents, hidden)]), encoding="utf-8")
        print(f"SARIF сохранён: {args.sarif}", file=sys.stderr)
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
