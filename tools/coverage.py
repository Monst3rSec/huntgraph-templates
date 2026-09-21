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
TECHNIQUES_DIR = os.path.join(ROOT, "hunt")
UPSTREAM_SOURCES = {"sigma"}   # third-party rules stored beside the templates

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

# Data components the CrowdStrike process, file and network telemetry this repo
# targets can actually supply. A technique whose analytics rest entirely on
# anything outside this set cannot be given an honest hypothesis here: the query
# would have to approximate the behaviour from command lines and would detect
# nothing. Those techniques are reported by --blocked rather than quietly
# skipped, so the gap stays visible and costed.
COLLECTABLE_COMPONENTS = {
    "Process Creation",
    "Process Metadata",
    "Command Execution",
    "Script Execution",
    "File Creation",
    "File Modification",
    "File Access",
    "File Metadata",
    "File Deletion",
    "Network Connection Creation",
    "Network Traffic Flow",
    "Network Traffic Content",
    "Network Share Access",
    "Windows Registry Key Creation",
    "Windows Registry Key Modification",
    "Windows Registry Key Access",
    "Windows Registry Key Deletion",
    "Service Creation",
    "Service Metadata",
    "Scheduled Job Creation",
    "Scheduled Job Modification",
    "User Account Creation",
    "User Account Modification",
    "User Account Metadata",
    "User Account Authentication",
    "Logon Session Creation",
    "Logon Session Metadata",
    "Active Directory Credential Request",
    "Active Directory Object Access",
    "Active Directory Object Modification",
    "Active Directory Object Creation",
    "Active Directory Object Deletion",
    "Application Log Content",
    "WMI Creation",
    "Image Metadata",
    "Volume Creation",
}


def corpus_coverage() -> dict[str, list[str]]:
    """Map ATT&CK id -> the hypothesis files that cover it."""
    covered: dict[str, list[str]] = {}
    if not os.path.isdir(TECHNIQUES_DIR):
        return covered
    for dirpath, dirs, files in os.walk(TECHNIQUES_DIR):
        dirs[:] = [d for d in dirs if d not in UPSTREAM_SOURCES]
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


def wazuh_coverage() -> dict[str, dict]:
    """ATT&CK id -> what the Wazuh side of its templates actually carries.

    Reported separately from `covered` because a template with only a CrowdStrike
    block is not covered for a Wazuh deployment, and a single "covered" column
    would say it was.
    """
    out: dict[str, dict] = {}
    if not os.path.isdir(TECHNIQUES_DIR):
        return out
    for dirpath, dirs, files in os.walk(TECHNIQUES_DIR):
        dirs[:] = [d for d in dirs if d not in UPSTREAM_SOURCES]
        for f in sorted(files):
            if not f.endswith((".yaml", ".yml")):
                continue
            try:
                with open(os.path.join(dirpath, f)) as fh:
                    doc = yaml.safe_load(fh)
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict) or "mitre" not in doc:
                continue
            blocks = [b for b in doc.get("query") or [] if b.get("platform") == "wazuh"]
            if not blocks:
                continue
            rules = sum(len(b["cases"]) for b in blocks)
            notp = sum(len(b["not_portable"]) for b in blocks)
            m = doc["mitre"]
            ids = list(m.get("sub_techniques") or []) or list(m.get("techniques") or [])
            for tid in ids:
                e = out.setdefault(tid, {"rules": 0, "not_portable": 0})
                e["rules"] += rules
                e["not_portable"] += notp
    return out


def skip_register() -> dict[str, str]:
    """Map ATT&CK id -> why this project deliberately does not cover it.

    A skip is a decision, not a backlog item. Keeping it separate from
    'not-covered' is what stops an acknowledged blind spot decaying into an
    unnoticed one.
    """
    path = os.path.join(ROOT, "skipped.yaml")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except yaml.YAMLError:
        return {}
    if not isinstance(doc, dict):
        return {}
    return {
        e["id"]: " ".join((e.get("reason") or "").split())
        for e in doc.get("skipped") or []
        if isinstance(e, dict) and e.get("id")
    }


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


def blocking_components(atk: Attack, technique, platform: str | None = None) -> set[str]:
    """Components an endpoint analytic needs that this repo cannot collect.

    Returns an empty set when at least one analytic is fully served by
    collectable components — that technique is workable.

    `platform` narrows the question to one operating system. This matters:
    without it a technique counts as reachable when *any* endpoint analytic is
    clean, which can be the Linux one while the Windows analytic still needs
    Module Load. Selecting a Windows target off the unfiltered list therefore
    risks citing an analytic the query cannot serve.
    """
    wanted = {platform} if platform else ENDPOINT_PLATFORMS
    needed = set()
    saw_endpoint_analytic = False
    for ds in atk.detection_strategies(technique):
        for a in ds["analytics"]:
            if not set(a["platforms"]) & wanted:
                continue
            saw_endpoint_analytic = True
            components = {
                ls["data_component"] for ls in a["log_sources"] if ls.get("data_component")
            }
            if not components:
                continue
            missing = components - COLLECTABLE_COMPONENTS
            if not missing:
                return set()  # this analytic is workable, technique is not blocked
            needed |= missing
    return needed if saw_endpoint_analytic else set()


def report_blocked(atk: Attack, covered: dict, args) -> int:
    tactics = PRIORITY_1 if args.priority != "2" else PRIORITY_2
    if args.tactic:
        tactics = [args.tactic]

    seen, rows = set(), []
    for tac in tactics:
        in_scope, _ = targets(atk, tac)
        for t in in_scope:
            tid = attack_id(t)
            if tid in covered or tid in seen:
                continue
            seen.add(tid)
            missing = blocking_components(atk, t, args.platform)
            if missing:
                rows.append({"id": tid, "name": t["name"], "missing": sorted(missing)})
    rows.sort(key=lambda r: r["id"])

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    print("\nUncovered targets blocked on uncollectable telemetry: %d\n" % len(rows))
    for r in rows:
        print("  %-12s %-46s %s" % (r["id"], r["name"][:46], ", ".join(r["missing"])))

    tally = {}
    for r in rows:
        for m in r["missing"]:
            tally[m] = tally.get(m, 0) + 1
    print("\n  unblocking these components would open:")
    for comp, n in sorted(tally.items(), key=lambda kv: -kv[1]):
        print("    %-32s %3d technique(s)" % (comp, n))
    return 0


def render_markdown(atk: Attack, covered: dict) -> str:
    """Emit task.md. Regenerate with: python3 tools/coverage.py --markdown > task.md"""
    out = []
    w = out.append

    techs = atk.live_techniques()
    subs = [t for t in techs if t.get("x_mitre_is_subtechnique")]
    release = atk.collection.get("x_mitre_version")

    w("# Task tracker")
    w("")
    w("Generated by `python3 tools/coverage.py --markdown > task.md`. Every number "
      "here is computed from the YAML on disk against the ATT&CK STIX bundle — do not "
      "edit this file by hand, it will be overwritten and it would be wrong in the "
      "meantime.")
    w("")
    w("## Scope")
    w("")
    w("| | |")
    w("|---|---|")
    w("| ATT&CK release | Enterprise v%s |" % release)
    w("| Live techniques and sub-techniques | %d (%d parents, %d sub-techniques) |"
      % (len(techs), len(techs) - len(subs), len(subs)))
    w("| Connector implemented | `crowdstrike-ngsiem` |")
    w("")
    w("A **target** is a leaf: a sub-technique, or a technique with no sub-techniques of "
      "its own. Parents that decompose are covered through their children, because a "
      "hypothesis pitched at the parent is too broad to yield an explainable verdict. "
      "A target is **in scope** when at least one of its platforms is Windows, Linux or "
      "macOS.")
    w("")

    for label, tactics in (("Priority 1", PRIORITY_1), ("Priority 2", PRIORITY_2)):
        w("## %s" % label)
        w("")
        w("| Tactic | Covered | In scope | Remaining | Out of scope |")
        w("|---|---:|---:|---:|---:|")
        unique = {}
        for tac in tactics:
            in_scope, out_scope = targets(atk, tac)
            done = [t for t in in_scope if attack_id(t) in covered]
            for t in in_scope:
                unique[attack_id(t)] = t
            pct = (100.0 * len(done) / len(in_scope)) if in_scope else 0.0
            w("| %s | %d (%.0f%%) | %d | %d | %d |"
              % (tac.replace("-", " ").title(), len(done), pct,
                 len(in_scope), len(in_scope) - len(done), len(out_scope)))
        udone = [tid for tid in unique if tid in covered]
        w("| **unique total** | **%d** | **%d** | **%d** | |"
          % (len(udone), len(unique), len(unique) - len(udone)))
        w("")
        skipped = skip_register()
        uskipped = sorted(tid for tid in unique if tid not in covered and tid in skipped)
        if uskipped:
            w("Of the %d remaining, **%d are recorded as deliberately skipped** in "
              "`skipped.yaml` — targets whose only observable is telemetry this "
              "deployment cannot collect, where any template would look like coverage "
              "and detect nothing. They are gaps, but acknowledged ones: %s."
              % (len(unique) - len(udone), len(uskipped), ", ".join(uskipped)))
            w("")

    # blocked analysis, Priority 1 only
    seen, rows = set(), []
    for tac in PRIORITY_1:
        in_scope, _ = targets(atk, tac)
        for t in in_scope:
            tid = attack_id(t)
            if tid in covered or tid in seen:
                continue
            seen.add(tid)
            missing = blocking_components(atk, t)
            if missing:
                rows.append(sorted(missing))
    tally = {}
    for missing in rows:
        for m in missing:
            tally[m] = tally.get(m, 0) + 1

    w("## Blocked on telemetry")
    w("")
    w("%d of the uncovered Priority 1 targets cannot be given an honest hypothesis with "
      "the process, file and network telemetry this repo targets. Their analytics rest "
      "entirely on data components the CrowdStrike endpoint sensor does not supply here."
      % len(rows))
    w("")
    w("| Missing data component | Targets it would unblock |")
    w("|---|---:|")
    for comp, n in sorted(tally.items(), key=lambda kv: -kv[1])[:8]:
        w("| %s | %d |" % (comp, n))
    w("")
    w("Confirming the NG-SIEM schema for module loads and process handle access is worth "
      "more than further authoring: it converts the largest single block of remaining "
      "work from impossible to routine. List them with "
      "`python3 tools/coverage.py --priority 1 --blocked`.")
    w("")
    w("## Next")
    w("")
    w("```bash")
    w("python3 tools/coverage.py --priority 1 --remaining   # what is left")
    w("python3 tools/coverage.py --priority 1 --blocked --platform Windows")
    w("python3 tools/validate.py --strict                   # contract check")
    w("python3 tools/test_validator.py                      # test the validator")
    w("```")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tactic", choices=TARGET_TACTICS)
    ap.add_argument("--priority", choices=["1", "2"], help="restrict to a priority tier")
    ap.add_argument("--remaining", action="store_true", help="list uncovered targets only")
    ap.add_argument("--blocked", action="store_true",
                    help="list uncovered targets blocked on telemetry this repo cannot collect")
    ap.add_argument("--platform", choices=sorted(ENDPOINT_PLATFORMS),
                    help="with --blocked, judge reachability for one platform only")
    ap.add_argument("--markdown", action="store_true",
                    help="emit the task.md tracker body")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    atk = Attack(load_bundle())
    covered = corpus_coverage()

    if args.markdown:
        print(render_markdown(atk, covered), end="")
        return 0

    if args.blocked:
        return report_blocked(atk, covered, args)

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
