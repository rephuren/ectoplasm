import argparse
import sys
import tempfile

from . import demo, render, trace, transcript


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="seance", description="Разбор сессии ИИ-агента после инцидента")
    sub = parser.add_subparsers(dest="mode", required=True)
    tr = sub.add_parser("trace", help="найти опасные действия и связать их с недоверенным текстом")
    tr.add_argument("session", help="журнал сессии Claude Code (.jsonl)")
    tr.add_argument("--min-confidence", choices=("weak", "medium", "strong"), default="medium", help="порог уверенности связи (по умолчанию medium)")
    tr.add_argument("--json", action="store_true")
    tr.add_argument("--no-color", action="store_true")
    dm = sub.add_parser("demo", help="синтетическая отравленная сессия: записать и разобрать")
    dm.add_argument("--out", metavar="ФАЙЛ", help="сохранить журнал демо в файл")
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
        incidents = trace.report(session)
        sys.stdout.write(render.text(session, incidents, sys.stdout.isatty() and not args.no_color))
        return 0

    try:
        session = transcript.load(args.session)
    except OSError as e:
        print(f"{args.session}: {e}", file=sys.stderr)
        return 2
    incidents = trace.report(session, args.min_confidence)
    if args.json:
        sys.stdout.write(render.as_json(session, incidents))
    else:
        sys.stdout.write(render.text(session, incidents, sys.stdout.isatty() and not args.no_color))
    return 1 if any(i.confidence == "strong" for i in incidents) else 0


if __name__ == "__main__":
    sys.exit(main())
