#!/usr/bin/env python3
"""Validate agentic threat-hunting detection YAML against the HuntGraph contract.

Five layers, run in order. L1 failures short-circuit a file; the rest all run so
one pass reports everything wrong with a template.

  L1 structure   YAML parses, conforms to schema/detection.schema.json (strict:
                 unknown keys are errors)
  L2 mitre       every ATT&CK id exists in the STIX bundle and the relationships
                 asserted by the file are the relationships MITRE actually
                 publishes (technique->tactic, sub->parent, DET->technique,
                 AN->DET)
  L3 evidence    evidence ids unique; risk_logic and verdict reference only ids
                 that exist; every evidence field is declared in requires.logs
  L4 query       CrowdStrike CQL only; no foreign dialects; queries reference
                 declared event types; baselines are complete when required
  L5 convention  directory layout, id format, id uniqueness across the corpus

    python3 tools/validate.py                    # whole repo
    python3 tools/validate.py techniques/T1218-*  # a subtree
    python3 tools/validate.py --strict           # warnings fail too
    python3 tools/validate.py --json             # machine readable

Requires: pyyaml, jsonschema  (pip install -r tools/requirements.txt)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

try:
    import yaml
    from jsonschema import Draft202012Validator
except ImportError as exc:  # pragma: no cover
    sys.exit("missing dependency (%s). pip install -r tools/requirements.txt" % exc)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_extract import Attack, attack_id, load_bundle  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(ROOT, "schema", "detection.schema.json")
TECHNIQUES_DIR = os.path.join(ROOT, "techniques")

# Rule ids are allocated to templates in blocks of this size. Wazuh ids must be
# globally unique, so a template may only use ids inside the block it owns.
RULE_BLOCK_SIZE = 16

# Evidence may come from correlation context that is not a raw log source.
PSEUDO_SOURCES = {
    "baseline",
    "threat_intel",
    "asset_inventory",
    "change_management",
    "identity_context",
    "derived",
}

# Tokens that betray a non-CQL dialect leaking into a query.
#
# The pipe-prefixed forms are anchored to the start of a line. CQL in this
# corpus puts its pipes there, whereas a bare "|" mid-line is almost always
# alternation inside a regex — Python's own eval( and exec( appear that way in
# a legitimate T1059.006 query, and an unanchored pattern flagged it as SPL.
FOREIGN_DIALECT = [
    (r"\bindex\s*=", "Splunk SPL (index=)"),
    (r"\bsourcetype\s*=", "Splunk SPL (sourcetype=)"),
    (r"^\s*\|\s*stats\b", "Splunk SPL (| stats)"),
    (r"^\s*\|\s*eval\b", "Splunk SPL (| eval)"),
    (r"^\s*\|\s*search\b", "Splunk SPL (| search)"),
    (r"^\s*\|\s*summarize\b", "Microsoft KQL (| summarize)"),
    (r"^\s*\|\s*project\b", "Microsoft KQL (| project)"),
    (r"^\s*\|\s*extend\b", "Microsoft KQL (| extend)"),
    (r"\bsequence\s+by\b", "Elastic EQL (sequence by)"),
    (r"\bSELECT\s+.+\bFROM\b", "SQL"),
    (r"^\s*detection\s*:", "Sigma"),
]

PLATFORM_MAP = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
    "esxi": "ESXi",
    "containers": "Containers",
    "iaas": "IaaS",
    "saas": "SaaS",
    "identity-provider": "Identity Provider",
    "office-suite": "Office Suite",
    "network-devices": "Network Devices",
}


class Report:
    def __init__(self, path: str):
        self.path = path
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, layer: str, msg: str) -> None:
        self.errors.append("[%s] %s" % (layer, msg))

    def warn(self, layer: str, msg: str) -> None:
        self.warnings.append("[%s] %s" % (layer, msg))

    @property
    def ok(self) -> bool:
        return not self.errors


# --------------------------------------------------------------------------
# L1 structure
# --------------------------------------------------------------------------
def check_structure(doc, schema, rep: Report) -> bool:
    validator = Draft202012Validator(schema)
    errs = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    for e in errs:
        loc = ".".join(str(p) for p in e.absolute_path) or "<root>"
        rep.error("L1", "%s: %s" % (loc, e.message))
    return not errs


# --------------------------------------------------------------------------
# L2 MITRE truth
# --------------------------------------------------------------------------
def check_mitre(doc, atk: Attack, rep: Report) -> None:
    m = doc["mitre"]

    for tac in m["tactics"]:
        if tac not in atk.by_attack_id or atk.by_attack_id[tac]["type"] != "x-mitre-tactic":
            rep.error("L2", "tactic %s does not exist in ATT&CK Enterprise" % tac)

    declared = list(m["techniques"]) + list(m["sub_techniques"])
    live = {}
    for tid in declared:
        obj = atk.by_attack_id.get(tid)
        if not obj or obj["type"] != "attack-pattern":
            rep.error("L2", "technique %s does not exist in ATT&CK Enterprise" % tid)
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            rep.error("L2", "technique %s is revoked/deprecated" % tid)
            continue
        live[tid] = obj

    # every declared tactic must be a kill-chain phase of some declared technique
    tactic_shortnames = set()
    for obj in live.values():
        tactic_shortnames |= {p["phase_name"] for p in obj.get("kill_chain_phases", [])}
    for tac in m["tactics"]:
        tacobj = atk.by_attack_id.get(tac)
        if tacobj and tacobj.get("x_mitre_shortname") not in tactic_shortnames:
            rep.error("L2", "tactic %s (%s) is not a tactic of any declared technique"
                      % (tac, tacobj["name"]))

    # sub-technique must belong to a declared parent
    for sid in m["sub_techniques"]:
        parent = sid.split(".")[0]
        if parent not in m["techniques"]:
            rep.error("L2", "sub-technique %s declared without parent %s in mitre.techniques"
                      % (sid, parent))

    # a hypothesis must be pitched at a leaf. Parents that decompose into
    # sub-techniques are covered through those, because a hypothesis at the
    # parent is too broad to produce an explainable verdict — and it silently
    # fails to count toward coverage, which is how this was first noticed.
    if not m["sub_techniques"]:
        for tid in m["techniques"]:
            children = sorted(
                aid for aid in atk.by_attack_id
                if aid.startswith(tid + ".")
                and atk.by_attack_id[aid]["type"] == "attack-pattern"
                and not atk.by_attack_id[aid].get("revoked")
                and not atk.by_attack_id[aid].get("x_mitre_deprecated")
            )
            if children:
                rep.error("L2", "%s decomposes into sub-techniques (%s); pitch the "
                                "hypothesis at the specific one it describes"
                          % (tid, ", ".join(children)))

    # detection strategies must actually detect a declared technique
    valid_ds = {}
    for tid, obj in live.items():
        for ds in atk.detection_strategies(obj):
            valid_ds[ds["id"]] = ds
    for det in m["detection_strategies"]:
        if det not in valid_ds:
            rep.error("L2", "%s is not a detection strategy MITRE maps to %s"
                      % (det, "/".join(declared)))

    # analytics must belong to a declared detection strategy
    valid_an = {}
    for det in m["detection_strategies"]:
        for a in valid_ds.get(det, {}).get("analytics", []):
            valid_an[a["id"]] = a
    for an in m["analytics"]:
        if an not in valid_an:
            rep.error("L2", "%s is not an analytic of the declared detection strategies" % an)

    # platforms must be a subset of the technique's platforms
    tech_platforms = set()
    for obj in live.values():
        tech_platforms |= set(obj.get("x_mitre_platforms", []))
    for p in m["platforms"]:
        if tech_platforms and p not in tech_platforms:
            rep.error("L2", "platform %r is not listed on %s (MITRE: %s)"
                      % (p, "/".join(declared), ", ".join(sorted(tech_platforms))))

    # data components must be reachable from the declared analytics
    reachable_dc, reachable_ls = set(), set()
    for an in m["analytics"]:
        for ls in valid_an.get(an, {}).get("log_sources", []):
            if ls.get("data_component"):
                reachable_dc.add(ls["data_component"])
            if ls.get("name"):
                reachable_ls.add(ls["name"])
    for dc in m["data_components"]:
        if reachable_dc and dc not in reachable_dc:
            rep.error("L2", "data component %r is not produced by the declared analytics (%s)"
                      % (dc, ", ".join(sorted(reachable_dc))))
    for ds_name in m["data_sources"]:
        if reachable_ls and ds_name not in reachable_ls:
            rep.warn("L2", "data source %r is not an ATT&CK log source for the declared "
                           "analytics (%s)" % (ds_name, ", ".join(sorted(reachable_ls))))

    # requires.platforms must be consistent with mitre.platforms
    for rp in doc["requires"]["platforms"]:
        if PLATFORM_MAP[rp] not in m["platforms"]:
            rep.error("L2", "requires.platforms %r has no matching mitre.platforms entry" % rp)

    # the technique URL must be cited
    urls = " ".join(doc["info"]["references"])
    for tid in declared:
        obj = live.get(tid)
        if obj and atk._url(obj) not in urls:
            rep.error("L2", "info.references must cite the MITRE page for %s (%s)"
                      % (tid, atk._url(obj)))


# --------------------------------------------------------------------------
# L3 evidence integrity
# --------------------------------------------------------------------------
def check_evidence(doc, rep: Report) -> None:
    ev = doc["evidence"]
    buckets = {k: ev[k] for k in ("required", "supporting", "contradicting")}

    ids, owner, seen = set(), {}, set()
    for bucket, items in buckets.items():
        for item in items:
            eid = item["id"]
            if eid in seen:
                rep.error("L3", "duplicate evidence id %r" % eid)
            seen.add(eid)
            ids.add(eid)
            owner[eid] = bucket

    def refs(where: str, values) -> None:
        for v in values:
            if v not in ids:
                rep.error("L3", "%s references unknown evidence id %r" % (where, v))

    rl = ev["risk_logic"]
    refs("risk_logic.required", rl["required"])
    refs("risk_logic.supporting.any", rl["supporting"]["any"])
    refs("risk_logic.supporting.all", rl["supporting"]["all"])
    refs("risk_logic.contradicting.any", rl["contradicting"]["any"])
    refs("risk_logic.contradicting.all", rl["contradicting"]["all"])

    required_ids = {i["id"] for i in buckets["required"]}
    if set(rl["required"]) != required_ids:
        rep.error("L3", "risk_logic.required %s must equal evidence.required ids %s"
                  % (sorted(rl["required"]), sorted(required_ids)))

    for key in ("any", "all"):
        for v in rl["supporting"][key]:
            if v in ids and owner[v] != "supporting":
                rep.error("L3", "risk_logic.supporting.%s cites %r which is %s evidence"
                          % (key, v, owner[v]))
        for v in rl["contradicting"][key]:
            if v in ids and owner[v] != "contradicting":
                rep.error("L3", "risk_logic.contradicting.%s cites %r which is %s evidence"
                          % (key, v, owner[v]))

    vd = ev["verdict"]
    for key in ("low_risk_when", "suspicious_when", "high_risk_when"):
        refs("verdict.%s" % key, vd[key])

    # a verdict must be reachable: escalation tiers build on required evidence
    for key in ("suspicious_when", "high_risk_when"):
        if not required_ids.issubset(set(vd[key])):
            rep.error("L3", "verdict.%s must include all required evidence %s"
                      % (key, sorted(required_ids)))
        for v in vd[key]:
            if v in ids and owner[v] == "contradicting":
                rep.error("L3", "verdict.%s cites contradicting evidence %r" % (key, v))
    if not any(owner.get(v) == "contradicting" for v in vd["low_risk_when"]):
        rep.error("L3", "verdict.low_risk_when must cite at least one contradicting evidence id")

    if len(vd["high_risk_when"]) <= len(vd["suspicious_when"]):
        rep.warn("L3", "verdict.high_risk_when (%d ids) is not stronger than suspicious_when "
                       "(%d ids)" % (len(vd["high_risk_when"]), len(vd["suspicious_when"])))

    # Every evidence field must be collectable from a declared log source — and
    # once a file declares more than one connector, from EVERY one of them.
    # Without the second half, a Wazuh block could claim evidence the Wazuh
    # telemetry never carries, which is this project's central failure mode
    # wearing a vendor label.
    #
    # set() over the fields value works for both shapes: a legacy list yields
    # vendor names, a migrated map yields the logical names that are its keys.
    connectors = doc["requires"]["connectors"]
    per_conn = {c: {} for c in connectors}
    for log in doc["requires"]["logs"]:
        conn = log_connector(log)
        if conn in per_conn:
            per_conn[conn][log["source"]] = set(log["fields"])

    for bucket, items in buckets.items():
        for item in items:
            src, field = item["source"], item["field"]
            if src in PSEUDO_SOURCES:
                continue
            for conn in connectors:
                declared = per_conn[conn]
                if src not in declared:
                    rep.error("L3", "evidence %r uses source %r which %s does not declare (%s)"
                              % (item["id"], src, conn, ", ".join(sorted(declared)) or "nothing"))
                elif field not in declared[src]:
                    rep.error("L3", "evidence %r uses field %r which %s does not declare under "
                                    "source %r" % (item["id"], field, conn, src))

    declared_fields = {}
    for log in doc["requires"]["logs"]:
        declared_fields.setdefault(log["source"], set()).update(log["fields"])

    unused = declared_fields.keys() - {
        i["source"] for items in buckets.values() for i in items
    }
    for src in sorted(unused):
        rep.warn("L3", "log source %r is declared but no evidence item uses it" % src)


# --------------------------------------------------------------------------
# L4 query hygiene
# --------------------------------------------------------------------------
_RULE_REGISTRY = None


def rule_id_registry() -> dict:
    """Template id -> allocated Wazuh rule-id block base. Cached per run."""
    global _RULE_REGISTRY
    if _RULE_REGISTRY is None:
        path = os.path.join(ROOT, "ruleset", "wazuh-id-allocations.yaml")
        try:
            doc = yaml.safe_load(open(path)) or {}
            _RULE_REGISTRY = doc.get("allocations") or {}
        except (OSError, yaml.YAMLError):
            _RULE_REGISTRY = {}
    return _RULE_REGISTRY


def log_connector(log: dict) -> str:
    """Which connector a requires.logs entry belongs to.

    Absent means crowdstrike-ngsiem: the corpus predates the second connector and
    unmigrated files carry no marker.
    """
    return log.get("connector", "crowdstrike-ngsiem")


def declared_events_for(doc, connector: str) -> set:
    return {
        e for log in doc["requires"]["logs"]
        if log_connector(log) == connector
        for e in log["event_types"]
    }


def check_query(doc, rep: Report) -> None:
    seen_cases = set()
    cql_case_ids = set()
    wazuh_blocks = []

    for block in doc["query"]:
        if block["platform"] == "wazuh":
            wazuh_blocks.append(block)
            continue
        declared_events = declared_events_for(doc, "crowdstrike-ngsiem")
        for case in block["cases"]:
            cid, q = case["id"], case["query"]
            if cid in seen_cases:
                rep.error("L4", "duplicate query case id %r" % cid)
            seen_cases.add(cid)
            cql_case_ids.add(cid)

            for pattern, dialect in FOREIGN_DIALECT:
                if re.search(pattern, q, re.IGNORECASE | re.MULTILINE):
                    rep.error("L4", "case %r looks like %s, not CrowdStrike CQL" % (cid, dialect))

            if "#event_simpleName" not in q and "#repo" not in q and "#Vendor" not in q:
                rep.error("L4", "case %r has no #event_simpleName / #repo tag; a CQL hunt must "
                                "constrain the event stream" % cid)

            if declared_events and not any(e in q for e in declared_events):
                rep.error("L4", "case %r references none of the declared event types (%s)"
                          % (cid, ", ".join(sorted(declared_events))))

            bl = case["baseline"]
            if bl["required"]:
                if not bl["window"]:
                    rep.error("L4", "case %r has baseline.required true but no window" % cid)
                if not bl["compare"]:
                    rep.error("L4", "case %r has baseline.required true but empty compare" % cid)
            else:
                if bl["window"] or bl["compare"]:
                    rep.warn("L4", "case %r sets baseline.required false but still defines "
                                   "window/compare" % cid)

            if len(q.strip().splitlines()) < 2:
                rep.warn("L4", "case %r is a single-line query; a one-condition hunt is usually "
                               "a weak indicator" % cid)

    for block in wazuh_blocks:
        check_wazuh_block(doc, block, cql_case_ids, rep)


def check_wazuh_block(doc, block, cql_case_ids: set, rep: Report) -> None:
    """A Wazuh rules block is a second expression of the same hypothesis.

    The load-bearing check is completeness: every CQL case must either have a rule
    mirroring it or be named in not_portable with a reason. Without that a partial
    port reads as a full one, which is this project's central failure mode wearing
    a vendor label.
    """
    rs = block["ruleset"]
    base = rs["base_id"]

    # The registry, not the file, is the authority on which block a template owns.
    # A template that picks its own base_id will eventually collide with another,
    # and a duplicate rule id makes every historical alert carrying it ambiguous.
    reg = rule_id_registry()
    owned = reg.get(doc["id"])
    if owned is None:
        rep.error("L4", "template has a wazuh block but no rule-id allocation; run "
                        "tools/alloc_rule_ids.py --alloc on this file")
    elif owned != base:
        rep.error("L4", "ruleset.base_id %d disagrees with the allocation registry (%d)"
                  % (base, owned))
    declared_lists = {l["path"] for l in rs["lists"]}
    used_ids = set()

    for case in block["cases"]:
        cid, xml = case["id"], case["rule"]

        try:
            root = ET.fromstring("<wrap>%s</wrap>" % xml)
        except ET.ParseError as exc:
            rep.error("L4", "wazuh case %r is not well-formed XML: %s" % (cid, exc))
            continue

        rules = root.findall("rule")
        if not rules:
            rep.error("L4", "wazuh case %r contains no <rule> element" % cid)
            continue

        for rule in rules:
            rid = rule.get("id")
            if not rid or not rid.isdigit():
                rep.error("L4", "wazuh case %r has a <rule> with no numeric id" % cid)
                continue
            rid = int(rid)
            if not base <= rid < base + RULE_BLOCK_SIZE:
                rep.error("L4", "wazuh case %r uses rule id %d outside its allocated block "
                                "%d-%d" % (cid, rid, base, base + RULE_BLOCK_SIZE - 1))
            if rid in used_ids:
                rep.error("L4", "wazuh rule id %d used more than once in this file" % rid)
            used_ids.add(rid)

            if not rule.get("level"):
                rep.error("L4", "wazuh rule %d has no level" % rid)

            mitre = [e.text for e in rule.findall("./mitre/id") if e.text]
            if not mitre:
                rep.error("L4", "wazuh rule %d declares no <mitre><id>" % rid)
            else:
                claimed = set(doc["mitre"]["sub_techniques"]) or set(doc["mitre"]["techniques"])
                stray = set(mitre) - claimed
                if stray:
                    rep.error("L4", "wazuh rule %d cites MITRE id(s) %s which the file does not "
                                    "declare (%s)"
                              % (rid, sorted(stray), sorted(claimed)))

            if not (rule.findall("if_group") or rule.findall("if_sid")
                    or rule.findall("if_matched_sid")):
                rep.error("L4", "wazuh rule %d chains from nothing; a rule with no if_group/"
                                "if_sid evaluates against every event on the manager" % rid)

            for lst in rule.findall("list"):
                if lst.text and lst.text.strip() not in declared_lists:
                    rep.error("L4", "wazuh rule %d references list %r which is not declared in "
                                    "ruleset.lists" % (rid, lst.text.strip()))

        if case["covers"] not in cql_case_ids:
            rep.error("L4", "wazuh case %r covers %r which is not a cql case id (%s)"
                      % (cid, case["covers"], ", ".join(sorted(cql_case_ids))))

        corr = case["correlation"]
        if corr["frequency"] and not corr["timeframe"]:
            rep.error("L4", "wazuh case %r sets frequency but no timeframe" % cid)

    covered = {c["covers"] for c in block["cases"]}
    excused = {n["case"] for n in block["not_portable"]}
    for stray in sorted(excused - cql_case_ids):
        rep.error("L4", "not_portable names %r which is not a cql case id" % stray)
    missing = cql_case_ids - covered - excused
    for m in sorted(missing):
        rep.error("L4", "cql case %r has no wazuh rule and is not listed in not_portable; a "
                        "partial port must say what it dropped" % m)
    both = covered & excused
    for b in sorted(both):
        rep.error("L4", "cql case %r is both covered by a wazuh rule and listed as "
                        "not_portable" % b)


# --------------------------------------------------------------------------
# L5 convention
# --------------------------------------------------------------------------
def check_convention(doc, path: str, rep: Report) -> None:
    rel = os.path.relpath(path, ROOT)
    parts = rel.split(os.sep)

    if parts[0] != "techniques":
        rep.error("L5", "detection files must live under techniques/, found %s" % rel)
        return
    if len(parts) not in (3, 4):
        rep.error("L5", "expected techniques/<Txxxx-slug>[/<Txxxx.yyy-slug>]/<name>.yaml, "
                        "found %s" % rel)
        return

    tech_dir = parts[1]
    mt = re.match(r"^(T\d{4})-[a-z0-9-]+$", tech_dir)
    if not mt:
        rep.error("L5", "technique directory %r must be <Txxxx>-<kebab-slug>" % tech_dir)
    elif mt.group(1) not in doc["mitre"]["techniques"]:
        rep.error("L5", "directory technique %s is not in mitre.techniques %s"
                  % (mt.group(1), doc["mitre"]["techniques"]))

    if len(parts) == 4:
        sub_dir = parts[2]
        ms = re.match(r"^(T\d{4}\.\d{3})-[a-z0-9-]+$", sub_dir)
        if not ms:
            rep.error("L5", "sub-technique directory %r must be <Txxxx.yyy>-<kebab-slug>" % sub_dir)
        elif ms.group(1) not in doc["mitre"]["sub_techniques"]:
            rep.error("L5", "directory sub-technique %s is not in mitre.sub_techniques %s"
                      % (ms.group(1), doc["mitre"]["sub_techniques"]))
    elif doc["mitre"]["sub_techniques"]:
        rep.error("L5", "file declares sub_techniques %s but sits directly under %s"
                  % (doc["mitre"]["sub_techniques"], tech_dir))

    fname = parts[-1]
    if not re.match(r"^[a-z0-9]+(-[a-z0-9]+)*\.yaml$", fname):
        rep.error("L5", "filename %r must be a kebab-case behaviour name ending .yaml" % fname)

    # the id must end with the most specific declared MITRE id
    most_specific = (doc["mitre"]["sub_techniques"] or doc["mitre"]["techniques"])[0]
    suffix = "-" + most_specific.lower().replace(".", "-")
    if not doc["id"].endswith(suffix):
        rep.error("L5", "id %r must end with %r (its most specific MITRE id)"
                  % (doc["id"], suffix))


# --------------------------------------------------------------------------
def validate_file(path: str, schema, atk: Attack) -> Report:
    rep = Report(path)
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        rep.error("L1", "YAML parse error: %s" % str(exc).replace("\n", " "))
        return rep
    if not isinstance(doc, dict):
        rep.error("L1", "top level must be a mapping")
        return rep

    if not check_structure(doc, schema, rep):
        return rep  # later layers assume a well-formed document

    check_mitre(doc, atk, rep)
    check_evidence(doc, rep)
    check_query(doc, rep)
    check_convention(doc, path, rep)
    return rep


def collect(paths: list[str]) -> list[str]:
    roots = paths or [TECHNIQUES_DIR]
    found = []
    for root in roots:
        if os.path.isfile(root):
            found.append(root)
            continue
        for dirpath, _, files in os.walk(root):
            for f in sorted(files):
                if f.endswith((".yaml", ".yml")):
                    found.append(os.path.join(dirpath, f))
    return sorted(set(found))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--strict", action="store_true", help="treat warnings as failures")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    with open(SCHEMA_PATH) as fh:
        schema = json.load(fh)
    atk = Attack(load_bundle())

    files = collect(args.paths)
    if not files:
        print("no detection YAML found")
        return 1

    reports = [validate_file(p, schema, atk) for p in files]

    # cross-file: ids must be unique
    by_id = defaultdict(list)
    for p in files:
        try:
            with open(p) as fh:
                d = yaml.safe_load(fh)
            if isinstance(d, dict) and isinstance(d.get("id"), str):
                by_id[d["id"]].append(os.path.relpath(p, ROOT))
        except yaml.YAMLError:
            pass
    dupes = {k: v for k, v in by_id.items() if len(v) > 1}
    for rep in reports:
        rel = os.path.relpath(rep.path, ROOT)
        for dup_id, paths in dupes.items():
            if rel in paths:
                rep.error("L5", "id %r is also used by %s"
                          % (dup_id, ", ".join(p for p in paths if p != rel)))

    n_err = sum(len(r.errors) for r in reports)
    n_warn = sum(len(r.warnings) for r in reports)
    n_bad = sum(1 for r in reports if r.errors)

    if args.json:
        print(json.dumps({
            "files": len(reports),
            "invalid": n_bad,
            "errors": n_err,
            "warnings": n_warn,
            "results": [
                {"file": os.path.relpath(r.path, ROOT), "errors": r.errors,
                 "warnings": r.warnings}
                for r in reports
            ],
        }, indent=2))
    else:
        for r in reports:
            rel = os.path.relpath(r.path, ROOT)
            if r.errors or r.warnings:
                print("\n%s" % rel)
                for e in r.errors:
                    print("  ERROR %s" % e)
                for w in r.warnings:
                    print("  WARN  %s" % w)
        print("\n%d files, %d valid, %d invalid, %d errors, %d warnings"
              % (len(reports), len(reports) - n_bad, n_bad, n_err, n_warn))

    if n_err:
        return 1
    if args.strict and n_warn:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
