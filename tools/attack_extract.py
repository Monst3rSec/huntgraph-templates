#!/usr/bin/env python3
"""Extract ground-truth MITRE ATT&CK facts for one or more techniques.

The generator must never invent MITRE data. This tool is the single source of
truth: it reads the Enterprise ATT&CK STIX bundle and prints, per technique,
everything the detection YAML is allowed to cite.

    python3 tools/attack_extract.py T1218.011 T1055.012
    python3 tools/attack_extract.py --tactic stealth --list
    python3 tools/attack_extract.py T1218.011 --json

The bundle is cached under ~/.cache/huntgraph/enterprise-attack.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from collections import defaultdict

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "refs/heads/master/enterprise-attack/enterprise-attack.json"
)
CACHE = os.path.expanduser("~/.cache/huntgraph/enterprise-attack.json")


def load_bundle(refresh: bool = False) -> dict:
    if refresh or not os.path.exists(CACHE):
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        sys.stderr.write("fetching %s\n" % STIX_URL)
        urllib.request.urlretrieve(STIX_URL, CACHE)
    with open(CACHE) as fh:
        return json.load(fh)


def attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


class Attack:
    def __init__(self, bundle: dict):
        self.objects = bundle["objects"]
        self.by_id = {o["id"]: o for o in self.objects}

        # ATT&CK ids are not unique across object types: deprecated mitigations
        # such as "Masquerading Mitigation" still carry T1036. Resolve to the
        # live, most specific object rather than whichever came first.
        self.by_attack_id = {}
        for o in self.objects:
            aid = attack_id(o)
            if not aid:
                continue
            current = self.by_attack_id.get(aid)
            if current is None or self._priority(o) > self._priority(current):
                self.by_attack_id[aid] = o

        self.collection = next(
            (o for o in self.objects if o["type"] == "x-mitre-collection"), {}
        )
        self.tactics = {
            o["x_mitre_shortname"]: o
            for o in self.objects
            if o["type"] == "x-mitre-tactic"
        }

        # relationship indexes
        self.rel_by_target = defaultdict(list)
        self.rel_by_source = defaultdict(list)
        for o in self.objects:
            if o["type"] == "relationship":
                self.rel_by_target[o["target_ref"]].append(o)
                self.rel_by_source[o["source_ref"]].append(o)

        # detection strategies index their analytics; analytics point at
        # techniques through `detects` relationships in v19.
        self.ds_by_analytic = {}
        for o in self.objects:
            if o["type"] == "x-mitre-detection-strategy":
                for ref in o.get("x_mitre_analytic_refs", []):
                    self.ds_by_analytic[ref] = o

    _TYPE_RANK = {
        "attack-pattern": 5,
        "x-mitre-tactic": 5,
        "x-mitre-detection-strategy": 5,
        "x-mitre-analytic": 5,
        "x-mitre-data-component": 4,
        "x-mitre-data-source": 4,
        "intrusion-set": 3,
        "campaign": 3,
        "malware": 3,
        "tool": 3,
        "course-of-action": 1,
    }

    @classmethod
    def _priority(cls, obj: dict) -> int:
        rank = cls._TYPE_RANK.get(obj["type"], 2)
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            rank -= 10
        return rank

    def live_techniques(self, tactic_shortname: str | None = None) -> list[dict]:
        out = []
        for o in self.objects:
            if o["type"] != "attack-pattern":
                continue
            if o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            phases = [p["phase_name"] for p in o.get("kill_chain_phases", [])]
            if tactic_shortname and tactic_shortname not in phases:
                continue
            out.append(o)
        return sorted(out, key=lambda t: attack_id(t) or "")

    def technique(self, tid: str) -> dict:
        obj = self.by_attack_id.get(tid)
        if not obj or obj["type"] != "attack-pattern":
            raise SystemExit("unknown technique id: %s" % tid)
        return obj

    def detection_strategies(self, technique: dict) -> list[dict]:
        """Detection strategies + their analytics for a technique."""
        found = {}
        for rel in self.rel_by_target[technique["id"]]:
            src = self.by_id.get(rel["source_ref"])
            if not src:
                continue
            if src["type"] == "x-mitre-detection-strategy":
                found.setdefault(src["id"], src)
            elif src["type"] == "x-mitre-analytic":
                ds = self.ds_by_analytic.get(src["id"])
                if ds:
                    found.setdefault(ds["id"], ds)
        result = []
        for ds in found.values():
            analytics = []
            for aref in ds.get("x_mitre_analytic_refs", []):
                a = self.by_id.get(aref)
                if not a:
                    continue
                log_sources = []
                for ls in a.get("x_mitre_log_source_references", []):
                    dc = self.by_id.get(ls.get("x_mitre_data_component_ref", ""))
                    log_sources.append(
                        {
                            "name": ls.get("name"),
                            "channel": ls.get("channel"),
                            "data_component": dc.get("name") if dc else None,
                            "data_component_id": attack_id(dc) if dc else None,
                        }
                    )
                analytics.append(
                    {
                        "id": attack_id(a),
                        "name": a.get("name"),
                        "description": a.get("description"),
                        "platforms": a.get("x_mitre_platforms", []),
                        "log_sources": log_sources,
                        "mutable_elements": a.get("x_mitre_mutable_elements", []),
                        "url": self._url(a),
                    }
                )
            result.append(
                {
                    "id": attack_id(ds),
                    "name": ds.get("name"),
                    "url": self._url(ds),
                    "analytics": analytics,
                }
            )
        return sorted(result, key=lambda d: d["id"] or "")

    def procedures(self, technique: dict) -> list[dict]:
        out = []
        for rel in self.rel_by_target[technique["id"]]:
            if rel.get("relationship_type") != "uses":
                continue
            src = self.by_id.get(rel["source_ref"])
            if not src or src["type"] not in (
                "intrusion-set",
                "malware",
                "tool",
                "campaign",
            ):
                continue
            out.append(
                {
                    "kind": src["type"],
                    "id": attack_id(src),
                    "name": src.get("name"),
                    "description": (rel.get("description") or "").strip(),
                }
            )
        return sorted(out, key=lambda p: (p["kind"], p["name"] or ""))

    def _url(self, obj: dict) -> str | None:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("url")
        return None

    def describe(self, tid: str) -> dict:
        t = self.technique(tid)
        tactics = []
        for p in t.get("kill_chain_phases", []):
            tac = self.tactics.get(p["phase_name"])
            if tac:
                tactics.append(
                    {"id": attack_id(tac), "name": tac["name"], "shortname": p["phase_name"]}
                )
        parent = None
        if t.get("x_mitre_is_subtechnique"):
            parent = tid.split(".")[0]
        data_components = sorted(
            {
                ls["data_component"]
                for ds in self.detection_strategies(t)
                for a in ds["analytics"]
                for ls in a["log_sources"]
                if ls.get("data_component")
            }
        )
        # ATT&CK v19 dropped the data-component -> data-source link. The
        # equivalent of a "data source" is now the analytic log-source name.
        data_sources = sorted(
            {
                ls["name"]
                for ds in self.detection_strategies(t)
                for a in ds["analytics"]
                for ls in a["log_sources"]
                if ls.get("name")
            }
        )
        return {
            "id": tid,
            "name": t["name"],
            "parent": parent,
            "url": self._url(t),
            "description": t.get("description", ""),
            "tactics": tactics,
            "platforms": t.get("x_mitre_platforms", []),
            "data_sources": data_sources,
            "data_components": data_components,
            "version": t.get("x_mitre_version"),
            "modified": t.get("modified"),
            "detection_strategies": self.detection_strategies(t),
            "procedures": self.procedures(t),
            "attack_release": self.collection.get("x_mitre_version"),
        }


def render(d: dict) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append("%s  %s   (ATT&CK %s, technique v%s, modified %s)" % (
        d["id"], d["name"], d["attack_release"], d["version"], d["modified"][:10]))
    lines.append(d["url"] or "")
    lines.append("tactics:    " + ", ".join("%s (%s)" % (t["name"], t["id"]) for t in d["tactics"]))
    lines.append("platforms:  " + ", ".join(d["platforms"]))
    lines.append("data srcs:  " + ", ".join(d["data_sources"]))
    lines.append("data comps: " + ", ".join(d["data_components"]))
    lines.append("")
    lines.append("--- description ---")
    lines.append(d["description"].strip())
    lines.append("")
    lines.append("--- detection strategies ---")
    for ds in d["detection_strategies"]:
        lines.append("[%s] %s" % (ds["id"], ds["name"]))
        lines.append("    %s" % ds["url"])
        for a in ds["analytics"]:
            lines.append("  (%s) %s  platforms=%s" % (a["id"], a["name"], ",".join(a["platforms"])))
            lines.append("      %s" % (a["description"] or "").replace("\n", " ")[:600])
            for ls in a["log_sources"]:
                lines.append("      log: %-28s channel=%-24s  [%s %s]" % (
                    ls["name"], ls["channel"], ls["data_component_id"], ls["data_component"]))
            for me in a["mutable_elements"]:
                lines.append("      mutable: %s — %s" % (me.get("field"), me.get("description")))
    lines.append("")
    lines.append("--- procedure examples (%d) ---" % len(d["procedures"]))
    for p in d["procedures"]:
        lines.append("  [%s %s] %s" % (p["kind"], p["id"], p["name"]))
        if p["description"]:
            lines.append("      %s" % p["description"].replace("\n", " ")[:400])
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("techniques", nargs="*", help="technique / sub-technique IDs")
    ap.add_argument("--tactic", help="tactic shortname, e.g. stealth")
    ap.add_argument("--list", action="store_true", help="list techniques for --tactic")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--refresh", action="store_true", help="re-download the STIX bundle")
    args = ap.parse_args()

    atk = Attack(load_bundle(args.refresh))

    if args.list:
        for t in atk.live_techniques(args.tactic):
            print("%-12s %-6s %s" % (
                attack_id(t),
                "sub" if t.get("x_mitre_is_subtechnique") else "",
                t["name"]))
        return 0

    if not args.techniques:
        ap.error("give technique IDs, or --tactic X --list")

    out = [atk.describe(tid) for tid in args.techniques]
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        for d in out:
            print(render(d))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
