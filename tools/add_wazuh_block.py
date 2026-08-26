#!/usr/bin/env python3
"""Migrate a batch of templates to logical fields and scaffold their Wazuh block.

Mechanical half of the Wazuh port. It does the parts that are deterministic:

  * rewrite requires.logs[].fields from a vendor list to a logical->vendor map,
    tag the entry with its connector, and add the matching wazuh entry
  * rewrite evidence[].field to the logical name
  * derive a first-pass <rule> for every CQL case that is a plain filter chain
  * put every remaining case in not_portable with a reason

It deliberately does NOT try to translate aggregation. A CQL case whose logic
lives in groupBy, case{} or a baseline comparison has no stateless equivalent,
and inventing one would produce a rule that looks like coverage and never fires.
Those become not_portable entries for a human to judge.

A template whose evidence cites a field Wazuh cannot supply is skipped entirely
and reported — declaring the connector anyway would fail the L3 cross-connector
check, which is the check working as intended.

    python3 tools/add_wazuh_block.py --limit 25
    python3 tools/add_wazuh_block.py techniques/T1036-*/T1036.007-*/*.yaml
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import textwrap
from xml.sax.saxutils import escape

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIELD_MAP = os.path.join(ROOT, "ruleset", "field-map.yaml")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from alloc_rule_ids import load as load_alloc, save as save_alloc, next_free  # noqa: E402

FILTER = re.compile(r"^\s*\|\s*([A-Za-z][A-Za-z0-9_]*)\s*(!?=)\s*/(.+)/([a-z]*)\s*$")
AGGREGATION = re.compile(r"\b(groupBy|case\s*\{|stdDev|bucket\(|formatTime|collect\()")

LEVEL = {"critical": 14, "high": 12, "medium": 8, "low": 5}


def load_map() -> dict:
    return yaml.safe_load(open(FIELD_MAP))["sources"]


def logical_for(smap: dict, source: str, vendor_field: str):
    for logical, d in smap.get(source, {}).get("fields", {}).items():
        if d.get("crowdstrike") == vendor_field:
            return logical
    return None


def rule_for_case(case: dict, source_of_event: dict, smap: dict, plat: str, rid: int,
                  sev: str, mitre_id: str, name: str):
    """First-pass rule from a plain filter chain, or None if the case aggregates."""
    q = case["query"]
    if case["baseline"]["required"]:
        return None, "Depends on a %s baseline comparison (%s); a stateless rule holds no history." % (
            case["baseline"]["window"], ", ".join(case["baseline"]["compare"]))

    body = [ln for ln in q.splitlines() if ln.strip()]
    filters, saw_agg = [], False
    source = None
    for ln in body:
        if ln.strip().startswith("#event_simpleName"):
            for src, ev in source_of_event.items():
                if any(e in ln for e in ev):
                    source = src
            continue
        if AGGREGATION.search(ln):
            saw_agg = True
            continue
        m = FILTER.match(ln)
        if m:
            filters.append(m.groups())

    if source is None:
        return None, "Could not resolve the CQL event selector to a declared log source."
    if not filters:
        return None, ("Carries no field-level filter a rule could match on; its logic is "
                      "entirely in aggregation.")

    anchors = smap[source]["anchors"].get(plat) or []
    if not anchors:
        return None, "No Wazuh decoder anchor is defined for %s on %s." % (source, plat)

    lines = ['<rule id="%d" level="%d">' % (rid, LEVEL.get(sev, 8)),
             "  <if_group>%s</if_group>" % anchors[0]]
    mapped, dropped = 0, []
    for fld, op, pattern, flags in filters:
        logical = logical_for(smap, source, fld)
        wfield = smap[source]["fields"].get(logical, {}).get(plat) if logical else None
        if not wfield:
            dropped.append(fld)
            continue
        # A named capture is a CQL idiom for feeding a later filter. Wazuh does
        # not bind it to anything, so keep the group non-capturing for clarity.
        pattern = re.sub(r"\(\?<[A-Za-z_][A-Za-z0-9_]*>", "(?:", pattern)
        pat = ("(?i)" if "i" in flags else "") + pattern
        neg = ' negate="yes"' if op == "!=" else ""
        lines.append('  <field name="%s" type="pcre2"%s>%s</field>' % (wfield, neg, escape(pat)))
        mapped += 1

    # Refuse rather than emit a broader rule than the CQL asked for. A dropped
    # filter is usually THE discriminator — a CQL-derived variable narrowing a
    # path to the writable ones, say — and a rule missing it still matches, still
    # validates, and fires on exactly the benign activity the case excluded.
    if dropped:
        return None, ("Its discriminator filters on %s, a CQL-derived variable or unmapped "
                      "field with no Wazuh equivalent. Emitting the rule without that "
                      "condition would broaden it to the benign activity the case exists to "
                      "exclude." % ", ".join(sorted(set(dropped))))
    if not mapped:
        return None, "None of the case's filter fields have a Wazuh equivalent on %s." % plat

    lines.append("  <description>%s</description>" % escape(name))
    lines.append("  <mitre><id>%s</id></mitre>" % mitre_id)
    lines.append("</rule>")
    note = ("Derived from the CQL filter chain; the aggregation in the original case is not "
            "represented." if saw_agg else None)
    return "\n".join(lines) + "\n", note


def render_logs(logs: list) -> str:
    """requires.logs as text, in the corpus's existing hand-written style."""
    out = ["  logs:"]
    for log in logs:
        out.append("    - source: %s" % log["source"])
        out.append("      connector: %s" % log["connector"])
        out.append("      event_types:")
        out += ["        - %s" % e for e in log["event_types"]]
        out.append("      fields:")
        out += ["        %s: %s" % (k, v) for k, v in log["fields"].items()]
    return "\n".join(out) + "\n"


def render_wazuh_block(block: dict) -> str:
    rs = block["ruleset"]
    o = ["  - platform: wazuh", "    language: wazuh-rules", "    ruleset:",
         "      base_id: %d" % rs["base_id"], "      group: %s" % rs["group"]]
    if rs["lists"]:
        o.append("      lists:")
        for l in rs["lists"]:
            o.append("        - path: %s" % l["path"])
            o.append("          purpose: >-")
            o += textwrap.wrap(l["purpose"], 88, initial_indent="            ",
                               subsequent_indent="            ")
    else:
        o.append("      lists: []")
    o.append("")
    o.append("    cases:")
    for c in block["cases"]:
        o.append("      - id: %s" % c["id"])
        o.append("        covers: %s" % c["covers"])
        o.append("        name: %s" % c["name"])
        o.append("        purpose: >-")
        o += textwrap.wrap(" ".join(c["purpose"].split()), 86,
                           initial_indent="          ", subsequent_indent="          ")
        o.append("        rule: |")
        o += ["          " + ln for ln in c["rule"].rstrip("\n").splitlines()]
        cr = c["correlation"]
        o.append("        correlation:")
        for k in ("frequency", "timeframe", "same_field"):
            o.append("          %s: %s" % (k, "null" if cr[k] is None else cr[k]))
        if c["limitations"]:
            o.append("        limitations:")
            for lim in c["limitations"]:
                w = textwrap.wrap(lim, 84, initial_indent="          - ",
                                  subsequent_indent="            ")
                o += w
        else:
            o.append("        limitations: []")
        o.append("")
    if block["not_portable"]:
        o.append("    not_portable:")
        for n in block["not_portable"]:
            o.append("      - case: %s" % n["case"])
            o.append("        reason: >-")
            o += textwrap.wrap(" ".join(n["reason"].split()), 86,
                               initial_indent="          ", subsequent_indent="          ")
    else:
        o.append("    not_portable: []")
    return "\n".join(o) + "\n"


def migrate(path: str, smap: dict, alloc: dict) -> tuple[bool, str]:
    raw = open(path).read()
    doc = yaml.safe_load(raw)
    if any(b["platform"] == "wazuh" for b in doc["query"]):
        return False, "already has a wazuh block"
    plat = doc["requires"]["platforms"][0]
    if plat not in ("windows", "linux", "macos"):
        return False, "platform %s has no Wazuh mapping" % plat

    logical_by_src = {}
    for log in doc["requires"]["logs"]:
        src = log["source"]
        lm = {}
        for vf in log["fields"]:
            lg = logical_for(smap, src, vf)
            if lg is None:
                return False, "no logical name for %s.%s" % (src, vf)
            lm[lg] = vf
        logical_by_src[src] = lm

    PSEUDO = {"baseline", "threat_intel", "asset_inventory", "change_management",
              "identity_context", "derived"}
    for bucket in ("required", "supporting", "contradicting"):
        for item in doc["evidence"][bucket]:
            if item["source"] in PSEUDO:
                continue
            lg = logical_for(smap, item["source"], item["field"])
            if lg is None:
                return False, "evidence %s cites unmapped %s.%s" % (
                    item["id"], item["source"], item["field"])
            if smap[item["source"]]["fields"][lg].get(plat) is None:
                return False, ("evidence %s needs %s, which Wazuh cannot supply on %s"
                               % (item["id"], lg, plat))

    new_logs, event_of_source = [], {}
    for log in doc["requires"]["logs"]:
        src = log["source"]
        event_of_source[src] = list(log["event_types"])
        new_logs.append({"source": src, "connector": "crowdstrike-ngsiem",
                         "event_types": list(log["event_types"]),
                         "fields": dict(logical_by_src[src])})
        wfields = {lg: smap[src]["fields"][lg][plat] for lg in logical_by_src[src]
                   if smap[src]["fields"][lg].get(plat)}
        anchors = smap[src]["anchors"].get(plat) or []
        if wfields and anchors:
            new_logs.append({"source": src, "connector": "wazuh",
                             "event_types": anchors, "fields": wfields})

    # Reserve provisionally. A template that turns out to have no expressible
    # case must not consume a block — the registry is meant to describe what
    # exists, and a phantom allocation makes later audits meaningless.
    provisional = doc["id"] not in alloc
    base = alloc.get(doc["id"]) or next_free(alloc)

    mitre_id = (doc["mitre"]["sub_techniques"] or doc["mitre"]["techniques"])[0]
    cases, notp, rid = [], [], base
    for block in doc["query"]:
        if block["platform"] != "crowdstrike":
            continue
        for c in block["cases"]:
            xml, note = rule_for_case(c, event_of_source, smap, plat, rid,
                                      doc["info"]["severity"], mitre_id, c["name"])
            if xml is None:
                notp.append({"case": c["id"], "reason": note})
                continue
            cases.append({"id": c["id"], "covers": c["id"], "name": c["name"],
                          "purpose": c["purpose"], "rule": xml,
                          "correlation": {"frequency": None, "timeframe": None,
                                          "same_field": None},
                          "limitations": [note] if note else []})
            rid += 1
    if not cases:
        return False, "no case is expressible as a stateless rule"
    if provisional:
        alloc[doc["id"]] = base

    tags = [t for t in doc["info"]["tags"] if t != plat][:2]
    group = ",".join(["huntgraph", plat] + tags)
    wblock = {"platform": "wazuh", "language": "wazuh-rules",
              "ruleset": {"base_id": base, "group": group, "lists": []},
              "cases": cases, "not_portable": notp}

    # Text surgery, not a re-dump: the corpus is hand-formatted and a yaml round
    # trip rewrites every folded block and list in the file, burying a 50-line
    # addition in 500 lines of noise.
    out = raw
    m = re.search(r"^  logs:\n(?:.*\n)*?(?=^query:$)", out, re.MULTILINE)
    if not m:
        return False, "could not locate requires.logs block"
    out = out[:m.start()] + render_logs(new_logs) + "\n" + out[m.end():]

    out = re.sub(r"(      source: (\w+)\n      field: )(\w+)",
                 lambda mm: mm.group(1) + (logical_for(smap, mm.group(2), mm.group(3))
                                           or mm.group(3)),
                 out)

    out = re.sub(r"^  connectors:\n    - crowdstrike-ngsiem\n",
                 "  connectors:\n    - crowdstrike-ngsiem\n    - wazuh\n", out,
                 count=1, flags=re.MULTILINE)

    ev = re.search(r"^evidence:$", out, re.MULTILINE)
    out = out[:ev.start()] + render_wazuh_block(wblock) + "\n" + out[ev.start():]

    open(path, "w").write(out)
    return True, "%d rule(s), %d not portable" % (len(cases), len(notp))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    paths = args.paths
    if not paths:
        paths = []
        for dp, _, fs in os.walk(os.path.join(ROOT, "techniques")):
            paths += [os.path.join(dp, f) for f in fs if f.endswith(".yaml")]
        paths.sort()

    smap, alloc = load_map(), load_alloc()
    done = skipped = 0
    for p in paths:
        if args.limit and done >= args.limit:
            break
        ok, why = migrate(p, smap, alloc)
        rel = os.path.relpath(p, ROOT)
        if ok:
            done += 1
            print("  ok    %-88s %s" % (rel[:88], why))
        else:
            skipped += 1
            print("  skip  %-88s %s" % (rel[:88], why))
    save_alloc(alloc)
    print("\nmigrated %d, skipped %d" % (done, skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
