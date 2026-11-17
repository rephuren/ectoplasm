"""Оценка правил на размеченных сценариях: python scripts/eval.py. Показывает пропуски и ложные срабатывания по подборочному и отложенному набору."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ectoplasm import sinks, trace, transcript  # noqa: E402
from tests.corpus.scenarios import SCENARIOS  # noqa: E402


def run_full(fn, floor="medium"):
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as fh:
        fh.write(fn().text())
    session = transcript.load(fh.name)
    return trace.report(session, floor), trace.hidden_text(session)


def run(fn, floor="medium"):
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as fh:
        fh.write(fn().text())
    return trace.report(transcript.load(fh.name), floor)


def evaluate(split, verbose=True):
    tp = fn_ = fp = tn = lim = 0
    rows = []
    for name, kind, expect, fn in SCENARIOS[split]:
        inc, hidden = run_full(fn)
        codes = {s.code for i in inc for s in i.sinks} | ({"hidden"} if hidden else set())
        if kind == "limit":
            ok = not inc and not hidden
            lim += ok
            if not ok:
                rows.append(f"  неожиданно найдено (граница из docs/CASES.md): {name}: {sorted(codes)}")
        elif kind == "attack":
            ok = expect in codes
            tp += ok
            fn_ += not ok
            if not ok:
                rows.append(f"  пропуск   {name}: ждали {expect}, получили {sorted(codes) or '—'}")
        else:
            ok = not inc and not hidden
            tn += ok
            fp += not ok
            if not ok:
                rows.append(f"  ложная    {name}: {sorted(codes)} ({inc[0].confidence})")
    if verbose:
        prec = tp / (tp + fp) if tp + fp else 1.0
        rec = tp / (tp + fn_) if tp + fn_ else 1.0
        print(f"{split}: атак {tp + fn_}, обычных {tn + fp}" + (f", заведомо невидимых {lim}" if lim else "") + f"; найдено {tp}, пропущено {fn_}, ложных {fp}; precision {prec:.2f}, recall {rec:.2f}")
        print("\n".join(rows))
    return tp, fn_, fp, tn


if __name__ == "__main__":
    assert sinks
    for split in ("train", "holdout", "hard", "public", "trifecta"):
        evaluate(split)
