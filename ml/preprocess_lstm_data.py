"""Shared deterministic preprocessing for the optional ETIS BiLSTM."""

from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "processed" / "dataset.csv"


def normalize_text(text: str) -> str:
    text = text.casefold()
    text = re.sub(r"[إأآٱ]", "ا", text)
    text = re.sub(r"ى", "ي", text)
    text = re.sub(r"ؤ", "و", text)
    text = re.sub(r"ئ", "ي", text)
    text = re.sub(r"[ًٌٍَُِّْـ]", "", text)
    text = re.sub(r"https?://\S+", " <url> ", text)
    return " ".join(text.split())


def load_splits() -> dict[str, tuple[list[str], list[int]]]:
    splits = {name: ([], []) for name in ("train", "val", "test")}
    with DATASET.open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            if row["content_type"] not in {"text", "email"}:
                continue
            texts, labels = splits[row["split"]]
            texts.append(normalize_text(row["text"]))
            labels.append(1 if row["label"] == "phishing" else 0)
    return splits


if __name__ == "__main__":
    data = load_splits()
    print({name: len(values[1]) for name, values in data.items()})
