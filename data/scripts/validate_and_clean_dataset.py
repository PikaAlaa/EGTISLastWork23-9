"""Validate and deterministically rebuild the locked ETIS dataset.

The split is group-aware: canonical-equivalent URLs and highly similar message
variants are always kept in one split so evaluation cannot benefit from leakage.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "dataset.csv"
REPORT_PATH = PROJECT_ROOT / "data" / "processed" / "dataset_cleaning_report.json"
EXPECTED_COLUMNS = [
    "id", "text", "content_type", "label", "language", "source",
    "brand_impersonated", "date_collected", "split",
]
ALLOWED = {
    "content_type": {"url", "text", "email"},
    "label": {"phishing", "legitimate"},
    "language": {"ar", "en", "mixed"},
    "split": {"train", "val", "test"},
}
SOURCE_PRIORITY = {
    "manual": 0, "synthetic_egyptian_brands": 1, "phishtank": 2,
    "openphish": 3, "tranco": 4,
}
LABEL_OVERRIDES = {
    "https://pokeapi.co": "legitimate",
    "https://kakaku.com": "legitimate",
}
NEAR_DUPLICATE_THRESHOLD = 0.92


def normalized_text(value: str) -> str:
    return " ".join(value.strip().split()).casefold()


def canonical_url(value: str) -> str:
    """Return a stable representation for URL equality and blacklist hashing."""
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.casefold() or "https"
        host = (parsed.hostname or "").casefold().rstrip(".")
        host = host.encode("idna").decode("ascii") if host else ""
        port = parsed.port
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            host = f"{host}:{port}"
        path = re.sub(r"/{2,}", "/", parsed.path or "/")
        if path != "/":
            path = path.rstrip("/")
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
        return urlunsplit((scheme, host, path if path != "/" else "", query, ""))
    except (UnicodeError, ValueError):
        return normalized_text(value).rstrip("/")


class DisjointSet:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, value: int) -> int:
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def build_leakage_groups(rows: list[dict[str, str]]) -> tuple[list[list[int]], int]:
    """Cluster canonical URLs and 0.92+ character-similar text/email rows."""
    dsu = DisjointSet(len(rows))
    urls: dict[str, int] = {}
    text_indexes: list[int] = []
    for index, row in enumerate(rows):
        if row["content_type"] == "url":
            key = canonical_url(row["text"])
            if key in urls:
                dsu.union(index, urls[key])
            else:
                urls[key] = index
        else:
            text_indexes.append(index)

    near_pairs = 0
    if len(text_indexes) > 1:
        corpus = [normalized_text(rows[index]["text"]) for index in text_indexes]
        matrix = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1).fit_transform(corpus)
        neighbors = NearestNeighbors(metric="cosine", algorithm="brute").fit(matrix)
        distances, indexes = neighbors.radius_neighbors(matrix, radius=1 - NEAR_DUPLICATE_THRESHOLD)
        for local_left, (row_distances, row_indexes) in enumerate(zip(distances, indexes)):
            for distance, local_right in zip(row_distances, row_indexes):
                if local_right <= local_left or 1 - float(distance) < NEAR_DUPLICATE_THRESHOLD:
                    continue
                dsu.union(text_indexes[local_left], text_indexes[int(local_right)])
                near_pairs += 1

    groups: dict[int, list[int]] = defaultdict(list)
    for index in range(len(rows)):
        groups[dsu.find(index)].append(index)
    return list(groups.values()), near_pairs


def assign_splits(rows: list[dict[str, str]]) -> dict[str, int]:
    """Greedily place whole leakage groups while preserving class/language/type ratios."""
    groups, near_pairs = build_leakage_groups(rows)
    rng = random.Random(42)
    rng.shuffle(groups)
    groups.sort(key=len, reverse=True)
    strata = [(row["label"], row["language"], row["content_type"]) for row in rows]
    totals = Counter(strata)
    targets = {
        split: {key: total * ratio for key, total in totals.items()}
        for split, ratio in (("train", 0.70), ("val", 0.15), ("test", 0.15))
    }
    assigned = {split: Counter() for split in targets}
    for group in groups:
        group_counts = Counter(strata[index] for index in group)
        best_split = min(
            targets,
            key=lambda split: sum(
                count * assigned[split][key] / max(1.0, targets[split][key])
                for key, count in group_counts.items()
            ) / len(group),
        )
        for index in group:
            rows[index]["split"] = best_split
        assigned[best_split].update(group_counts)
    return {"near_duplicate_pairs_grouped": near_pairs, "leakage_groups": len(groups)}


def validate(rows: list[dict[str, str]], columns: list[str] | None) -> list[str]:
    errors: list[str] = []
    if columns != EXPECTED_COLUMNS:
        errors.append(f"columns must be {EXPECTED_COLUMNS!r}; got {columns!r}")
    ids = Counter(row.get("id", "") for row in rows)
    duplicate_ids = sorted(key for key, count in ids.items() if count > 1)
    if duplicate_ids:
        errors.append(f"duplicate IDs: {duplicate_ids[:10]!r}")
    for index, row in enumerate(rows, start=2):
        for field in ("id", "text", "content_type", "label", "language", "source", "date_collected", "split"):
            if not row.get(field, "").strip():
                errors.append(f"row {index}: empty {field}")
        for field, allowed in ALLOWED.items():
            if row.get(field) not in allowed:
                errors.append(f"row {index}: invalid {field}={row.get(field)!r}")
        if len(errors) >= 100:
            break

    by_exact: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_url: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_exact[normalized_text(row["text"])].append(row)
        if row["content_type"] == "url":
            by_url[canonical_url(row["text"])].append(row)
    conflicts = [group for group in by_exact.values() if len({row["label"] for row in group}) > 1]
    exact_leakage = [group for group in by_exact.values() if len({row["split"] for row in group}) > 1]
    url_leakage = [group for group in by_url.values() if len({row["split"] for row in group}) > 1]
    if conflicts:
        errors.append(f"{len(conflicts)} normalized-text groups have conflicting labels")
    if exact_leakage:
        errors.append(f"{len(exact_leakage)} normalized-text groups cross split boundaries")
    if url_leakage:
        errors.append(f"{len(url_leakage)} canonical-URL groups cross split boundaries")
    return errors


def clean(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], dict]:
    by_identity: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        key = canonical_url(row["text"]) if row["content_type"] == "url" else normalized_text(row["text"])
        by_identity[f'{row["content_type"]}:{key}'].append(row)

    cleaned: list[dict[str, str]] = []
    removed: list[dict[str, str]] = []
    resolved: list[dict[str, object]] = []
    unresolved: list[str] = []
    for identity, group in by_identity.items():
        labels = {row["label"] for row in group}
        key = identity.split(":", 1)[1]
        if len(labels) > 1:
            override = LABEL_OVERRIDES.get(key)
            if override is None:
                unresolved.append(group[0]["text"])
                continue
            candidates = [row for row in group if row["label"] == override]
            resolved.append({"identity": key, "labels": sorted(labels), "kept_label": override})
        else:
            candidates = group
        candidates.sort(key=lambda row: (SOURCE_PRIORITY.get(row["source"], 99), row["id"]))
        kept = candidates[0]
        cleaned.append(kept)
        removed.extend(row for row in group if row is not kept)

    if unresolved:
        raise ValueError(f"Unresolved conflicting labels: {unresolved[:10]!r}")
    split_report = assign_splits(cleaned)
    cleaned.sort(key=lambda row: row["id"])
    report = {
        "input_rows": len(rows),
        "output_rows": len(cleaned),
        "canonical_or_exact_duplicates_removed": len(removed),
        "resolved_label_conflicts": resolved,
        **split_report,
        "split_counts": dict(Counter(row["split"] for row in cleaned)),
        "label_counts": dict(Counter(row["label"] for row in cleaned)),
        "removed_ids": [row["id"] for row in removed],
    }
    return cleaned, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="repair duplicates and rebuild the split")
    args = parser.parse_args()
    with DATASET_PATH.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        columns = reader.fieldnames
    if args.write:
        try:
            prior_report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            prior_report = {}
        rows, report = clean(rows)
        if prior_report.get("output_rows") == report["input_rows"]:
            report["source_input_rows"] = prior_report.get("source_input_rows", prior_report["input_rows"])
            report["canonical_or_exact_duplicates_removed"] += prior_report.get("canonical_or_exact_duplicates_removed", 0)
            report["resolved_label_conflicts"] = prior_report.get("resolved_label_conflicts", []) + report["resolved_label_conflicts"]
        else:
            report["source_input_rows"] = report["input_rows"]
        with DATASET_PATH.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=EXPECTED_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, ensure_ascii=False))
    errors = validate(rows, columns)
    if errors:
        print("Dataset validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"Dataset valid: {len(rows):,} rows; no exact/canonical cross-split leakage.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
