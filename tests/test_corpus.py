import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from eval import evaluate, run  # noqa: E402

from tests.corpus.scenarios import SCENARIOS  # noqa: E402


def test_train_and_holdout_have_no_misses_or_false_alarms():
    for split in ("train", "holdout"):
        tp, fn, fp, tn = evaluate(split, verbose=False)
        assert (fn, fp) == (0, 0), split
        assert tp >= 8 and tn >= 9


def test_hard_set_known_limits():
    missed = []
    for name, kind, _expect, fn in SCENARIOS["hard"]:
        found = bool(run(fn))
        if kind == "benign":
            assert not found, name
        elif not found:
            missed.append(name)
    assert missed == ["x_package_name_only"]  # название пакета из недоверенного текста без других признаков не ловится, это записано в README


def test_every_attack_names_its_sink():
    for split in SCENARIOS.values():
        for name, kind, expect, _fn in split:
            assert (kind == "attack") == (expect is not None), name
