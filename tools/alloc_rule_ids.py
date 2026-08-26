#!/usr/bin/env python3
"""Allocate and verify Wazuh rule-id blocks, one per detection template.

Wazuh rule ids must be globally unique across a manager's whole ruleset, and the
user range starts at 100000. With hundreds of templates that cannot be tracked by
hand, so the allocation lives in a registry file the validator treats as
authoritative — the same side-file pattern as skipped.yaml.

    python3 tools/alloc_rule_ids.py --check          # verify, exit 1 on a problem
    python3 tools/alloc_rule_ids.py --alloc PATH...  # reserve blocks for templates
    python3 tools/alloc_rule_ids.py --list

A block is RULE_BLOCK_SIZE ids wide. The largest template in the corpus has five
query cases, so a block of 16 leaves room for a rule per case plus correlation
rules chained off them.
"""

from __future__ import annotations

import argparse
import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "ruleset", "wazuh-id-allocations.yaml")
BLOCK_SIZE = 16
RANGE_START = 100000
RANGE_END = 120000

HEADER = """# Wazuh rule-id block allocations.
#
# One block per detection template, %d ids wide, keyed by the template's hg- id.
# Wazuh rule ids must be unique across the entire manager ruleset, so nothing here
# may overlap and nothing may be reused after a template is deleted — retiring an
# id and then handing it to a different rule makes historical alerts lie about what
# fired.
#
# Maintained by tools/alloc_rule_ids.py. Verified by tools/validate.py.

allocations:
""" % BLOCK_SIZE


def load() -> dict:
    if not os.path.isfile(REGISTRY):
        return {}
    doc = yaml.safe_load(open(REGISTRY)) or {}
    return doc.get("allocations") or {}


def save(alloc: dict) -> None:
    os.makedirs(os.path.dirname(REGISTRY), exist_ok=True)
    with open(REGISTRY, "w") as fh:
        fh.write(HEADER)
        for tid in sorted(alloc, key=lambda k: alloc[k]):
            fh.write("  %s: %d\n" % (tid, alloc[tid]))


def template_ids(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        doc = yaml.safe_load(open(p))
        if isinstance(doc, dict) and doc.get("id"):
            out.append(doc["id"])
    return out


def next_free(alloc: dict) -> int:
    used = set(alloc.values())
    cand = RANGE_START
    while cand in used:
        cand += BLOCK_SIZE
    if cand + BLOCK_SIZE > RANGE_END:
        sys.exit("rule id range %d-%d exhausted" % (RANGE_START, RANGE_END))
    return cand


def check(alloc: dict) -> int:
    problems = []
    seen = {}
    for tid, base in sorted(alloc.items(), key=lambda kv: kv[1]):
        if base % BLOCK_SIZE != RANGE_START % BLOCK_SIZE:
            problems.append("%s: base %d is not on a %d-id boundary" % (tid, base, BLOCK_SIZE))
        if not RANGE_START <= base < RANGE_END:
            problems.append("%s: base %d outside the user range %d-%d"
                            % (tid, base, RANGE_START, RANGE_END))
        if base in seen:
            problems.append("%s and %s both claim base %d" % (seen[base], tid, base))
        seen[base] = tid
    for p in problems:
        print("  ERROR %s" % p)
    print("%d allocations, %d problems" % (len(alloc), len(problems)))
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--alloc", nargs="*", default=None,
                    help="template yaml paths to reserve blocks for")
    args = ap.parse_args()

    alloc = load()

    if args.alloc is not None:
        added = 0
        for tid in template_ids(args.alloc):
            if tid in alloc:
                continue
            alloc[tid] = next_free(alloc)
            added += 1
            print("  %-70s -> %d" % (tid, alloc[tid]))
        save(alloc)
        print("allocated %d new block(s); %d total" % (added, len(alloc)))
        return 0

    if args.list:
        for tid in sorted(alloc, key=lambda k: alloc[k]):
            print("  %-70s %d-%d" % (tid, alloc[tid], alloc[tid] + BLOCK_SIZE - 1))
        return 0

    return check(alloc)


if __name__ == "__main__":
    sys.exit(main())
