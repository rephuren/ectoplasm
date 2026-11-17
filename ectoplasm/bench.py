"""Прогон набора данных с разметкой: ectoplasm bench <папка> (см. dataset/ectoplasm-bench-v1). Так же можно прогнать и чужой детектор: достаточно файла labels.json и журналов."""
import json
from pathlib import Path

from . import trace, transcript


def run(root: Path, fmt: str = "auto") -> dict:
    labels = json.loads((root / "labels.json").read_text(encoding="utf-8"))
    splits: dict[str, dict] = {}
    for item in labels["items"]:
        session = transcript.load(root / item["file"], fmt=fmt)
        incidents = trace.report(session, "medium")
        hidden = trace.hidden_text(session)
        codes = {s.code for i in incidents for s in i.sinks} | ({"hidden"} if hidden else set())
        sp = splits.setdefault(item["split"], {"attacks": 0, "found": 0, "missed": [], "benign": 0, "false": [], "limits": 0, "limit_broken": []})
        kind, expect = item["kind"], item.get("expect")
        if kind == "attack":
            sp["attacks"] += 1
            if expect in codes:
                sp["found"] += 1
            else:
                sp["missed"].append(item["id"])
        elif kind == "benign":
            sp["benign"] += 1
            if incidents or hidden:
                sp["false"].append(item["id"])
        else:
            sp["limits"] += 1
            if incidents or hidden:
                sp["limit_broken"].append(item["id"])
    return {"name": labels.get("name"), "splits": splits}


def text(result: dict) -> str:
    out = [f"{result['name']}"]
    for name, sp in result["splits"].items():
        found, att = sp["found"], sp["attacks"]
        fp = len(sp["false"])
        prec = found / (found + fp) if found + fp else 1.0
        rec = found / att if att else 1.0
        out.append(f"  {name:<10} атак {att}, обычных {sp['benign']}" + (f", заведомо невидимых {sp['limits']}" if sp["limits"] else "")
                   + f": найдено {found}, пропущено {len(sp['missed'])}, ложных {fp}; precision {prec:.2f}, recall {rec:.2f}")
        out += [f"    пропуск {m}" for m in sp["missed"]] + [f"    ложная  {m}" for m in sp["false"]] + [f"    неожиданно найдено (граница) {m}" for m in sp["limit_broken"]]
    return "\n".join(out) + "\n"
