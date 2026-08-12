#!/usr/bin/env python3
"""Export the full ATT&CK Enterprise matrix with this repo's coverage status.

One row per (tactic, technique-or-sub-technique). A technique in three tactics
produces three rows, because coverage is a question you ask per tactic.

    python3 tools/export_csv.py > coverage.csv
    python3 tools/export_csv.py --priority 1 > priority1.csv

Columns:
    tactic_id, tactic
    technique_id, technique            parent technique
    subtechnique_id, subtechnique      blank for techniques with no children
    is_leaf                            yes when this row is a hunting target
    platforms
    detection_strategies, analytics    MITRE ids backing the row
    data_components_required           what MITRE says the analytics need
    data_components_missing            of those, what this repo cannot collect
    status                             see below
    hypotheses, files                  what covers it, if anything

status values:
    covered            a hypothesis exists in this repo
    not-covered        reachable and outstanding
    blocked-telemetry  no analytic is fully served by collectable telemetry
    out-of-scope       no Windows, Linux or macOS platform
    parent             decomposes into sub-techniques; covered through them
"""

from __future__ import annotations

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_extract import Attack, attack_id, load_bundle  # noqa: E402
from coverage import (  # noqa: E402
    COLLECTABLE_COMPONENTS,
    ENDPOINT_PLATFORMS,
    PRIORITY_1,
    PRIORITY_2,
    blocking_components,
    corpus_coverage,
)

COLUMNS = [
    "tactic_id",
    "tactic",
    "priority",
    "technique_id",
    "technique",
    "subtechnique_id",
    "subtechnique",
    "is_leaf",
    "platforms",
    "detection_strategies",
    "analytics",
    "data_components_required",
    "data_components_missing",
    "status",
    "hypotheses",
    "files",
]


def priority_of(shortname: str) -> str:
    if shortname in PRIORITY_1:
        return "1"
    if shortname in PRIORITY_2:
        return "2"
    return ""


def build_rows(atk: Attack, covered: dict, only_priority: str | None) -> list[dict]:
    tactic_objs = {t["x_mitre_shortname"]: t for t in atk.tactics.values()}

    # which parents decompose
    live = atk.live_techniques()
    subs = [t for t in live if t.get("x_mitre_is_subtechnique")]
    has_children = {attack_id(t).split(".")[0] for t in subs}

    rows = []
    for tech in live:
        tid = attack_id(tech)
        if not tid:
            continue
        is_sub = bool(tech.get("x_mitre_is_subtechnique"))
        parent_id = tid.split(".")[0] if is_sub else tid
        parent = atk.by_attack_id.get(parent_id)
        platforms = tech.get("x_mitre_platforms", [])
        in_scope = bool(set(platforms) & ENDPOINT_PLATFORMS)
        leaf = is_sub or tid not in has_children

        strategies = atk.detection_strategies(tech)
        det_ids = [d["id"] for d in strategies if d["id"]]
        an_ids = sorted({
            a["id"] for d in strategies for a in d["analytics"] if a["id"]
        })
        components = sorted({
            ls["data_component"]
            for d in strategies for a in d["analytics"] for ls in a["log_sources"]
            if ls.get("data_component")
        })
        missing = sorted(set(components) - COLLECTABLE_COMPONENTS) if components else []

        files = covered.get(tid, [])
        if not leaf:
            status = "parent"
        elif files:
            status = "covered"
        elif not in_scope:
            status = "out-of-scope"
        elif blocking_components(atk, tech):
            status = "blocked-telemetry"
        else:
            status = "not-covered"

        for phase in tech.get("kill_chain_phases", []):
            shortname = phase.get("phase_name")
            tac = tactic_objs.get(shortname)
            if not tac:
                continue
            prio = priority_of(shortname)
            if only_priority and prio != only_priority:
                continue
            rows.append({
                "tactic_id": attack_id(tac),
                "tactic": tac["name"],
                "priority": prio,
                "technique_id": parent_id,
                "technique": parent["name"] if parent else "",
                "subtechnique_id": tid if is_sub else "",
                "subtechnique": tech["name"] if is_sub else "",
                "is_leaf": "yes" if leaf else "no",
                "platforms": "; ".join(platforms),
                "detection_strategies": "; ".join(det_ids),
                "analytics": "; ".join(an_ids),
                "data_components_required": "; ".join(components),
                "data_components_missing": "; ".join(missing),
                "status": status,
                "hypotheses": len(files),
                "files": "; ".join(files),
            })

    rows.sort(key=lambda r: (r["tactic_id"], r["technique_id"], r["subtechnique_id"]))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--priority", choices=["1", "2"], help="restrict to a priority tier")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    args = ap.parse_args()

    atk = Attack(load_bundle())
    rows = build_rows(atk, corpus_coverage(), args.priority)

    fh = open(args.output, "w", newline="") if args.output else sys.stdout
    try:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if args.output:
            fh.close()

    if args.output:
        tally = {}
        for r in rows:
            tally[r["status"]] = tally.get(r["status"], 0) + 1
        sys.stderr.write("%d rows -> %s\n" % (len(rows), args.output))
        for k, v in sorted(tally.items(), key=lambda kv: -kv[1]):
            sys.stderr.write("  %-18s %d\n" % (k, v))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
