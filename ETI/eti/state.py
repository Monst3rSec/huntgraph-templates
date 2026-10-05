"""What one run needs to remember for the next, as three CSV files.

`seen.csv` is every item a run has observed, emitted or not, so tomorrow's run reports
only what is new. `feeds.csv` is one row per source with its failure streak, which is
what turns a feed that quietly stopped working into something visible. `drafted.csv` is
the leads that already have a template draft, so a story that keeps being republished
does not accumulate one draft per retelling.

All three are committed by the scheduled job. That is the whole persistence story: no cache,
no database, and a diff anyone can read.
"""

from __future__ import annotations

import csv
import os
from datetime import datetime, timedelta
from pathlib import Path

SEEN_COLUMNS = ("key", "source_id", "first_seen")
FEED_COLUMNS = ("source_id", "status", "error", "entries", "in_window", "emitted",
                "last_ok", "fail_streak", "last_run")
# Which leads already have a draft. Keyed by the lead's canonical URL, because that is
# what survives a headline being edited after publication.
DRAFTED_COLUMNS = ("url", "draft_id", "drafted", "title")

# A key is forgotten only once it is both this old and gone from its feed. Age alone is
# not enough: a slow blog keeps a post in its feed for a year, and forgetting it would
# report it as new again.
SEEN_RETENTION_DAYS = 90


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_rows(path: Path, columns: tuple[str, ...], rows: list[dict]) -> None:
    """Write via a temp file, so a run killed mid-write leaves the old file intact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore",
                                lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, path)


def load_seen(state_dir: Path) -> dict[str, dict[str, str]]:
    return {row["key"]: row for row in read_rows(state_dir / "seen.csv")}


def save_seen(state_dir: Path, seen: dict[str, dict[str, str]], observed: set[str],
              now: datetime) -> None:
    cutoff = (now - timedelta(days=SEEN_RETENTION_DAYS)).date().isoformat()
    kept = [row for key, row in seen.items()
            if key in observed or row["first_seen"] >= cutoff]
    # Sorted by first sight then key, so a day's new rows land together at the end and
    # the commit diff is an append rather than a shuffle.
    kept.sort(key=lambda r: (r["first_seen"], r["key"]))
    write_rows(state_dir / "seen.csv", SEEN_COLUMNS, kept)


def load_feeds(state_dir: Path) -> dict[str, dict[str, str]]:
    return {row["source_id"]: row for row in read_rows(state_dir / "feeds.csv")}


def save_feeds(state_dir: Path, rows: list[dict]) -> None:
    write_rows(state_dir / "feeds.csv", FEED_COLUMNS,
               sorted(rows, key=lambda r: r["source_id"]))


def load_drafted(state_dir: Path) -> dict[str, dict[str, str]]:
    return {row["url"]: row for row in read_rows(state_dir / "drafted.csv")}


def save_drafted(state_dir: Path, drafted: dict[str, dict[str, str]]) -> None:
    rows = sorted(drafted.values(), key=lambda r: (r.get("drafted", ""), r.get("url", "")))
    write_rows(state_dir / "drafted.csv", DRAFTED_COLUMNS, rows)
