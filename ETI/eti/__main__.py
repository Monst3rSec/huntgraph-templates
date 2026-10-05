"""`python -m eti` — one aggregation run.

The summary is printed as Markdown because the scheduled job appends it to the GitHub
step summary; in a terminal it reads fine as it is.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from .fetch import DEFAULT_WORKERS, fetch_stream
from .pipeline import Report, run

HERE = Path(__file__).resolve().parent.parent


def _summary(report: Report, top: int) -> str:
    if report.aborted:
        failed = [f for f in report.feeds if f["status"] == "failed"]
        errors = Counter(f["error"] for f in failed).most_common(5)
        lines = [f"## ETI {report.stamp}: aborted", "", report.aborted, ""]
        lines += [f"- {n} x {err}" for err, n in errors]
        return "\n".join(lines)

    bands = Counter(r["band"] for r in report.rows)
    lines = [
        f"## ETI {report.stamp}",
        "",
        f"- output: `{report.path}`",
        f"- items: {len(report.rows)} new "
        f"({bands['high']} high, {bands['medium']} medium, {bands['low']} low)",
        f"- feeds: {report.count('ok')} ok, {report.count('failed')} failed, "
        f"{report.count('skipped')} skipped",
        f"- drafts: {len(report.drafts)} new template draft(s)",
    ]
    if report.drafts:
        lines += ["", "### Template drafts", "", "| draft | lead |", "|---|---|"]
        for rec in report.drafts:
            title = rec["title"].replace("|", "\\|")[:90]
            lines.append(f"| `{rec['draft_id']}` | [{title}]({rec['url']}) |")
    if report.rows:
        lines += ["", f"### Top {min(top, len(report.rows))}", "",
                  "| conf | source | others | title |", "|---:|---|---:|---|"]
        for row in report.rows[:top]:
            title = row["title"].replace("|", "\\|")[:110]
            lines.append(f"| {row['confidence']} | {row['source_id']} | "
                         f"{row['other_publishers']} | [{title}]({row['url']}) |")
    failed = sorted((f for f in report.feeds if f["status"] == "failed"),
                    key=lambda f: -int(f["fail_streak"]))
    if failed:
        lines += ["", "### Failed feeds", "", "| source | streak | error |", "|---|---:|---|"]
        lines += [f"| {f['source_id']} | {f['fail_streak']} | {f['error']} |" for f in failed]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="eti", description=__doc__.splitlines()[0])
    p.add_argument("--feeds", type=Path, default=HERE / "security_feeds.yaml")
    p.add_argument("--scoring", type=Path, default=HERE / "scoring.yaml")
    p.add_argument("--out", type=Path, default=HERE / "output")
    p.add_argument("--state", type=Path, default=HERE / "state")
    p.add_argument("--templates", type=Path, default=HERE / "templates",
                   help="where template drafts are written (default ETI/templates)")
    p.add_argument("--draft-band", action="append", choices=["high", "medium", "low"],
                   help="bands that earn a draft; repeatable (default: high only)")
    p.add_argument("--draft-limit", type=int, default=0,
                   help="most drafts to write in one run; 0 is no limit")
    p.add_argument("--no-drafts", action="store_true",
                   help="score and write the CSV, but write no template drafts")
    p.add_argument("--window-hours", type=int, default=72,
                   help="how far back a dated item may be and still count as new (default 72)")
    p.add_argument("--min-ok-ratio", type=float, default=0.5,
                   help="abort without writing if fewer feeds than this could be read")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                   help=f"feeds in flight at once (default {DEFAULT_WORKERS})")
    p.add_argument("--timeout", type=float, default=25.0)
    p.add_argument("--top", type=int, default=15, help="rows shown in the summary")
    p.add_argument("--no-state", action="store_true",
                   help="write the CSV but leave state/ untouched, so the run can be repeated")
    args = p.parse_args(argv)

    report = run(
        feeds_path=args.feeds, scoring_path=args.scoring, out_dir=args.out,
        state_dir=args.state, window_hours=args.window_hours,
        min_ok_ratio=args.min_ok_ratio, write_state=not args.no_state,
        drafts_dir=None if args.no_drafts else args.templates,
        draft_bands=tuple(args.draft_band or ("high",)),
        draft_limit=args.draft_limit,
        fetcher=lambda sources: fetch_stream(sources, workers=args.workers,
                                             timeout=args.timeout),
    )
    print(_summary(report, args.top))
    return 2 if report.aborted else 0


if __name__ == "__main__":
    sys.exit(main())
