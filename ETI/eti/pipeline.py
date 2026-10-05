"""One run: fetch, decide what is new, score it, write the CSV, update state."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from . import draft as draft_mod
from . import state
from .corroborate import corroborate
from .fetch import FeedResult, Item, fetch_stream
from .score import load_scoring, reliability, score
from .signals import extract
from .sources import Source, load_sources

OUTPUT_COLUMNS = (
    "confidence", "band", "published_utc", "age_hours", "source_id", "source",
    "categories", "title", "url", "tags", "cves", "attack_ids_mentioned", "actors",
    "ioc_count", "behaviours", "other_publishers", "corroborated_by",
    "score_source", "score_corroboration", "score_specificity", "score_relevance",
    "text_basis", "notes",
)

# A publish date this far ahead of the clock is a broken feed, not timezone slop.
_FUTURE_TOLERANCE = timedelta(hours=24)

# Returns the results, or yields them as they land. The pipeline iterates either
# way, so a streaming fetcher lets the work below overlap the network wait.
Fetcher = Callable[[list[Source]], Iterable[FeedResult]]


@dataclass
class Report:
    stamp: str
    path: Path | None = None
    rows: list[dict] = field(default_factory=list)
    feeds: list[dict] = field(default_factory=list)
    drafts: list[dict] = field(default_factory=list)
    aborted: str = ""

    def count(self, status: str) -> int:
        return sum(1 for f in self.feeds if f["status"] == status)


def _safe_cell(value: str) -> str:
    """Stop a feed title being run as a formula by whatever opens the CSV.

    Titles come from other people's websites. A cell starting with one of these is
    evaluated by Excel and Sheets, so it is quoted into plain text.
    """
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value


def filename_for(now: datetime) -> str:
    # No colons: they are illegal in Windows filenames and in artifact names.
    return now.strftime("%Y-%m-%dT%H%M%SZ")


def run(*, feeds_path: Path, scoring_path: Path, out_dir: Path, state_dir: Path,
        now: datetime | None = None, window_hours: int = 72, min_ok_ratio: float = 0.5,
        fetcher: Fetcher = fetch_stream, write_state: bool = True,
        drafts_dir: Path | None = None, draft_bands: tuple[str, ...] = ("high",),
        draft_limit: int = 0) -> Report:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    report = Report(stamp=filename_for(now))
    cfg = load_scoring(scoring_path)
    sources = load_sources(feeds_path)
    enabled = [s for s in sources if s.enabled]

    # The fetcher yields each feed as it lands (fetch_stream) or returns a list (the
    # tests). Either way it is consumed as an iterator, and the signal extraction for
    # everything already inside the window is done here, in the gaps, while the slow
    # hosts are still in flight. It is the same work either way -- only its position
    # relative to the network wait changes.
    window_start = now - timedelta(hours=window_hours)

    def dated(item: Item) -> bool:
        return item.published is not None and item.published <= now + _FUTURE_TOLERANCE

    def placeable(item: Item) -> bool:
        """Whether the item's date can be trusted to say it is inside the window."""
        return dated(item) and not item.batch_dated

    results: list[FeedResult] = []
    early: dict[str, object] = {}
    for result in fetcher(enabled):
        results.append(result)
        for item in result.items:
            if item.key not in early and placeable(item) and item.published >= window_start:
                early[item.key] = extract(item.title, item.body)
    ok_count = sum(1 for r in results if r.ok)

    previous = state.load_feeds(state_dir)
    seen = state.load_seen(state_dir)
    today = now.date().isoformat()

    # If most feeds failed, the problem is here — no network, a blocked runner — and
    # not out there. Writing state from such a run would charge every source a failure
    # and publish a near-empty CSV that reads as a quiet day, so nothing is written.
    if enabled and ok_count / len(enabled) < min_ok_ratio:
        report.aborted = (f"only {ok_count} of {len(enabled)} feeds could be read; "
                          "nothing written")
        report.feeds = [{"source_id": r.source.id, "status": "ok" if r.ok else "failed",
                         "error": r.error} for r in results]
        return report

    # The same URL can arrive through two feeds. Keep it once, under the more reliable.
    by_key: dict[str, Item] = {}
    for result in results:
        for item in result.items:
            held = by_key.get(item.key)
            if held is None or reliability(item.source, cfg) > reliability(held.source, cfg):
                by_key[item.key] = item

    emit: list[Item] = []
    pool: list[Item] = []
    for item in by_key.values():
        in_window = placeable(item) and item.published >= window_start
        # An item whose date is missing, in the future or a batch stamp cannot be
        # placed in the window, so it is new only relative to what this source showed
        # last time. On a source's first run there is no last time, and that backlog is
        # recorded as seen rather than reported as today's news.
        unplaced_new = (not placeable(item) and item.key not in seen
                        and bool(previous.get(item.source.id, {}).get("last_ok")))
        if in_window or unplaced_new:
            pool.append(item)
            if item.key not in seen:
                emit.append(item)

    # Corroboration is judged against everything in the window, including items already
    # reported: yesterday's research post still corroborates today's news story.
    # Mostly cache hits: everything in the window was extracted as its feed arrived.
    # The misses are the undated and batch-dated items, which cannot be recognised as
    # belonging to the pool until `seen` and the per-source history have been consulted.
    signals = {item.key: early.get(item.key) or extract(item.title, item.body)
               for item in pool}
    others = corroborate(pool, signals, threshold=cfg.similarity_threshold,
                         cve_roundup_limit=cfg.cve_roundup_limit)

    rows = []
    for item in emit:
        sig = signals[item.key]
        result = score(item.source, sig, len(others[item.key]), cfg)
        is_dated = dated(item)
        notes = ("undated" if item.published is None else
                 f"future-dated {item.published.date().isoformat()}" if not is_dated else
                 "batch-dated" if item.batch_dated else "")
        rows.append({
            "confidence": result.confidence,
            "band": result.band,
            "published_utc": item.published.strftime("%Y-%m-%dT%H:%M:%SZ") if is_dated else "",
            "age_hours": round((now - item.published).total_seconds() / 3600, 1) if is_dated else "",
            "source_id": item.source.id,
            "source": item.source.name,
            "categories": ";".join(item.source.categories),
            "title": _safe_cell(item.title),
            "url": item.url,
            "tags": ";".join(sig.tags),
            "cves": ";".join(sig.cves),
            "attack_ids_mentioned": ";".join(sig.attack_ids),
            "actors": ";".join(sig.actors),
            "ioc_count": sig.ioc_count,
            "behaviours": ";".join(sig.behaviours),
            "other_publishers": len(others[item.key]),
            "corroborated_by": ";".join(others[item.key]),
            "score_source": result.source,
            "score_corroboration": result.corroboration,
            "score_specificity": result.specificity,
            "score_relevance": result.relevance,
            "text_basis": sig.text_basis,
            "notes": notes,
        })
    # Highest confidence first, newest first within a score. The URL sort underneath
    # makes the order fully determined, so two runs over the same input diff clean.
    rows.sort(key=lambda r: r["url"])
    rows.sort(key=lambda r: r["published_utc"], reverse=True)
    rows.sort(key=lambda r: r["confidence"], reverse=True)
    report.rows = rows

    # Per-feed accounting. `emitted` is by the source the row is attributed to, so it
    # can be lower than a feed's new entries when another feed carried the same URL.
    emitted_by = {}
    for item in emit:
        emitted_by[item.source.id] = emitted_by.get(item.source.id, 0) + 1
    by_source = {r.source.id: r for r in results}
    for source in sources:
        prior = previous.get(source.id, {})
        result = by_source.get(source.id)
        if result is None:
            report.feeds.append({**{c: prior.get(c, "") for c in state.FEED_COLUMNS},
                                 "source_id": source.id, "status": "skipped",
                                 "error": f"status: {source.status}", "last_run": today})
            continue
        report.feeds.append({
            "source_id": source.id,
            "status": "ok" if result.ok else "failed",
            "error": result.error,
            "entries": len(result.items),
            "in_window": sum(1 for i in result.items
                             if placeable(i) and i.published >= window_start),
            "emitted": emitted_by.get(source.id, 0),
            "last_ok": today if result.ok else prior.get("last_ok", ""),
            "fail_streak": 0 if result.ok else int(prior.get("fail_streak") or 0) + 1,
            "last_run": today,
        })

    out_dir.mkdir(parents=True, exist_ok=True)
    report.path = out_dir / f"{report.stamp}.csv"
    # Written even when empty: a header-only file is the record that the run happened
    # and found nothing, which a missing file cannot say.
    state.write_rows(report.path, OUTPUT_COLUMNS, rows)

    # Template drafts. The CSV is the record of the run; a draft is the start of a piece
    # of work, so only leads that cleared the band get one, and only once each.
    if drafts_dir is not None:
        drafted = state.load_drafted(state_dir)
        report.drafts = draft_mod.write_drafts(rows, drafts_dir, now=now,
                                               bands=draft_bands, drafted=drafted,
                                               limit=draft_limit)
        if write_state and report.drafts:
            for rec in report.drafts:
                drafted[rec["url"]] = rec
            state.save_drafted(state_dir, drafted)

    if write_state:
        for item in by_key.values():
            seen.setdefault(item.key, {"key": item.key, "source_id": item.source.id,
                                       "first_seen": today})
        state.save_seen(state_dir, seen, set(by_key), now)
        state.save_feeds(state_dir, report.feeds)
    return report
