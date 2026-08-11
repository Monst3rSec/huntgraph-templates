#!/usr/bin/env python3
"""Report hypothesis coverage per ATT&CK tactic.

Answers the only question that matters between iterations: what is left, and
what was deliberately left out. Coverage is computed from the corpus on disk,
never from a hand-maintained list, so it cannot go stale.

    python3 tools/coverage.py                     # all target tactics
    python3 tools/coverage.py --tactic stealth    # one tactic
    python3 tools/coverage.py --remaining         # just the to-do list
    python3 tools/coverage.py --json

A technique is a *target* when it is a leaf: a sub-technique, or a technique
with no sub-techniques of its own. Parents that decompose into sub-techniques
are covered through those, because a hypothesis pitched at the parent is too
broad to yield an explainable verdict.

A target is *out of scope* when none of its platforms are Windows, Linux or
macOS. The only implemented connector is the CrowdStrike endpoint sensor, and
forcing a detection where the telemetry does not exist is worse than declaring
the gap.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_extract import Attack, attack_id, load_bundle  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TECHNIQUES_DIR = os.path.join(ROOT, "techniques")

PRIORITY_1 = [
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "lateral-movement",
]
PRIORITY_2 = [
    "discovery",
    "collection",
    "command-and-control",
    "exfiltration",
]
TARGET_TACTICS = PRIORITY_1 + PRIORITY_2
ENDPOINT_PLATFORMS = {"Windows", "Linux", "macOS"}


def corpus_coverage() -> dict[str, list[str]]:
    """Map ATT&CK id -> the hypothesis files that cover it."""
    covered: dict[str, list[str]] = {}
    if not os.path.isdir(TECHNIQUES_DIR):
        return covered
    for dirpath, _, files in os.walk(TECHNIQUES_DIR):
        for f in sorted(files):
            if not f.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(dirpath, f)
            try:
                with open(path) as fh:
                    doc = yaml.safe_load(fh)
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict) or "mitre" not in doc:
                continue
            m = doc["mitre"]
            ids = list(m.get("sub_techniques") or []) or list(m.get("techniques") or [])
            for tid in ids:
                covered.setdefault(tid, []).append(os.path.relpath(path, ROOT))
    return covered


def targets(atk: Attack, tactic: str) -> tuple[list, list]:
    """(in-scope targets, out-of-scope targets) for a tactic."""
    techs = atk.live_techniques(tactic)
    subs = [t for t in techs if t.get("x_mitre_is_subtechnique")]
    has_subs = {attack_id(t).split(".")[0] for t in subs}
    leaves = subs + [
        t for t in techs
        if not t.get("x_mitre_is_subtechnique") and attack_id(t) not in has_subs
    ]
    leaves.sort(key=lambda t: attack_id(t) or "")

    in_scope, out_scope = [], []
    for t in leaves:
        if set(t.get("x_mitre_platforms", [])) & ENDPOINT_PLATFORMS:
            in_scope.append(t)
        else:
            out_scope.append(t)
    return in_scope, out_scope


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tactic", choices=TARGET_TACTICS)
    ap.add_argument("--priority", choices=["1", "2"], help="restrict to a priority tier")
    ap.add_argument("--remaining", action="store_true", help="list uncovered targets only")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    atk = Attack(load_bundle())
    covered = corpus_coverage()
    if args.tactic:
        tactics = [args.tactic]
    elif args.priority == "1":
        tactics = PRIORITY_1
    elif args.priority == "2":
        tactics = PRIORITY_2
    else:
        tactics = TARGET_TACTICS

    result = {}
    for tac in tactics:
        in_scope, out_scope = targets(atk, tac)
        done = [t for t in in_scope if attack_id(t) in covered]
        todo = [t for t in in_scope if attack_id(t) not in covered]
        result[tac] = {
            "in_scope": len(in_scope),
            "covered": len(done),
            "remaining": len(todo),
            "out_of_scope": len(out_scope),
            "hypotheses": sum(len(covered[attack_id(t)]) for t in done),
            "remaining_ids": [
                {"id": attack_id(t), "name": t["name"],
                 "platforms": t.get("x_mitre_platforms", [])}
                for t in todo
            ],
            "out_of_scope_ids": [
                {"id": attack_id(t), "name": t["name"],
                 "platforms": t.get("x_mitre_platforms", [])}
                for t in out_scope
            ],
        }

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    for tac, r in result.items():
        pct = (100.0 * r["covered"] / r["in_scope"]) if r["in_scope"] else 0.0
        print("\n%s" % tac)
        print("  targets in scope   %3d" % r["in_scope"])
        print("  covered            %3d  (%.1f%%, %d hypotheses)"
              % (r["covered"], pct, r["hypotheses"]))
        print("  remaining          %3d" % r["remaining"])
        print("  out of scope       %3d  (no Windows/Linux/macOS telemetry)"
              % r["out_of_scope"])
        if args.remaining:
            for t in r["remaining_ids"]:
                print("      %-12s %-52s %s"
                      % (t["id"], t["name"][:52], ",".join(t["platforms"])))

    # techniques belong to several tactics (T1574 is Stealth, Persistence and
    # Privilege Escalation at once), so summing per-tactic counts overstates
    # the work. Report the unique target set.
    unique = {}
    for tac in tactics:
        in_scope, _ = targets(atk, tac)
        for t in in_scope:
            unique[attack_id(t)] = t
    done = [tid for tid in unique if tid in covered]
    print("\nunique targets %d, covered %d, remaining %d"
          % (len(unique), len(done), len(unique) - len(done)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
