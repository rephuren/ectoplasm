"""Выгрузка корпуса в открытый набор данных: python scripts/export_dataset.py [папка]. По умолчанию dataset/ectoplasm-bench-v1."""
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.corpus.scenarios import SCENARIOS  # noqa: E402

DATASHEET = """# ectoplasm-bench-v1: набор синтетических сессий агентов с разметкой

## Зачем
Мало открытых наборов, где есть **журнал сессии агента** и разметка «в нём есть навязанное недоверенным текстом действие или нет». Этот набор нужен, чтобы сравнивать детекторы происхождения (какой текст привёл к опасному действию) на общих данных, а не на выборочных примерах из статей.

## Состав
- {total} сессий в формате журнала Claude Code (jsonl): {attacks} с атакой, {benign} обычной работы, {limits} «заведомо невидимых по журналу».
- Разбиение: `train` (на нём настраивались правила), `holdout` (написан отдельно), `hard` (перефразированные атаки и похожая на атаку обычная работа), `public` (реконструкция десяти опубликованных кейсов), `trifecta` (тройка без характерных слов).
- `labels.json`: на каждую сессию `kind` (`attack`, `benign`, `limit`), для атак `expect` (код опасного действия, которое должно быть найдено, или `hidden` для скрытого текста) и описание.

## Как собрано
Все сессии придуманы автором скриптом `tests/corpus/scenarios.py`. Это не реальные журналы: нет личных данных, домены в зоне `.test`. Тексты атак сделаны по описаниям исследователей (источники в docs/CASES.md), не дословно.

## Известные перекосы
- **Автор один**, знает правила детектора. Результаты `train` и `public` оптимистичны по построению; наборы `holdout` и `hard` написаны отдельно, но тем же человеком.
- Сессии короткие (3-30 событий), в реальных журналах их тысячи и шума больше. Ложные срабатывания на реальных длинных журналах здесь не измеряются.
- Нет атак на других языках, кроме русского и английского, и нет атак через изображения и аудио.
- «Заведомо невидимые» случаи (`limit`) описывают границу метода: детектор не должен их находить, потому что в журнале нет текста, который к ним привёл.

## Как использовать
```bash
ectoplasm bench dataset/ectoplasm-bench-v1
```
Для другого детектора: прочитайте `labels.json`, прогоните файлы из `items[].file` и сравните с `kind` и `expect`.

## Лицензия
MIT, как и репозиторий. Данные синтетические, ограничений на использование нет.
"""


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dataset" / "ectoplasm-bench-v1"
    if out.exists():
        shutil.rmtree(out)
    items = []
    for split, scenarios in SCENARIOS.items():
        (out / split).mkdir(parents=True)
        for name, kind, expect, fn in scenarios:
            rel = f"{split}/{name}.jsonl"
            (out / rel).write_text(fn().text(), encoding="utf-8")
            doc = (fn.__doc__ or "").strip().split("\n")[0]
            items.append({"id": name, "split": split, "file": rel, "kind": kind, **({"expect": expect} if expect else {}), **({"note": doc} if doc else {})})
    counts = {k: sum(i["kind"] == k for i in items) for k in ("attack", "benign", "limit")}
    (out / "labels.json").write_text(json.dumps({"name": "ectoplasm-bench-v1", "format": "claude-code-jsonl", "items": items}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "DATASHEET.md").write_text(DATASHEET.format(total=len(items), attacks=counts["attack"], benign=counts["benign"], limits=counts["limit"]), encoding="utf-8")
    print(f"сохранено: {out} ({len(items)} сессий)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
