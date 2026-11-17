"""Пересобрать assets/demo.png: HTML-отчёт демо-сессии, снятый в Chrome без интерфейса. Нужен установленный Chrome (путь можно задать CHROME)."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ectoplasm import demo, htmlreport, trace, transcript  # noqa: E402

CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "demo.jsonl"
        demo.write(str(log))
        session = transcript.load(log)
        session.path = "demo (синтетическая сессия)"
        page = Path(tmp) / "demo.html"
        page.write_text(htmlreport.render(session, trace.report(session)), encoding="utf-8")
        out = ROOT / "assets" / "demo.png"
        subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--screenshot={out}", "--window-size=1100,1250", page.as_uri()],
                       check=True, capture_output=True, timeout=60)
    print(f"сохранено: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
