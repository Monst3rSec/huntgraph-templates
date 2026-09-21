#!/usr/bin/env python3
"""Triage upstream Splunk and Elastic detection rules against this corpus.

Writes splunk_tracker.md and elk_tracker.md: one row per upstream rule, with the
routing decision and why. Both are generated artefacts — regenerate, never hand-edit.

    python3 tools/track_sources.py                 # fetch upstream, rewrite trackers
    python3 tools/track_sources.py --inventory X   # reuse a cached inventory json

A rule is only queued for conversion when its technique is a leaf this repo does not
cover, is observable on Windows/Linux/macOS, is not missing the telemetry the hypothesis
would need, and carries at least one ATT&CK detection strategy (without one it cannot
satisfy L2).
"""
from __future__ import annotations
import argparse, collections, csv, glob, json, os, re, sys, urllib.request
import concurrent.futures as cf
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import validate as V  # noqa: E402

SPLUNK = "https://raw.githubusercontent.com/splunk/security_content/develop/"
ELASTIC = "https://raw.githubusercontent.com/elastic/detection-rules/main/"
ENDPOINT = {"Windows", "Linux", "macOS"}

REASON = {
    "convert":              "leaf target this repo does not cover, endpoint-observable, telemetry available",
    "staged-unmapped":      "no ATT&CK mapping upstream — staged, not a template",
    "covered":              "a template already covers every technique it cites",
    "blocked-telemetry":    "needs a data component this deployment does not collect",
    "out-of-scope":         "no Windows/Linux/macOS platform (cloud, SaaS, container)",
    "parent":               "parent technique, covered through its sub-techniques",
    "skipped":              "recorded in skipped.yaml as a deliberate gap",
    "no-detection-strategy":"ATT&CK publishes no detection strategy, so L2 cannot pass",
    "unresolved-id":        "technique id not in the ATT&CK release this repo pins",
    "non-endpoint-surface": "upstream rule does not read endpoint telemetry (cloud, SaaS, network, mail, or it declares no data source at all)",
    "fetch-error":          "upstream file could not be read",
}
ENDPOINT_SRC = re.compile(
    r"sysmon|winevent|windows event|security event|endpoint|endgame|auditbeat|winlogbeat|"
    r"auditd|osquery|unifiedlog|process|file system|filebeat-?windows|logs-windows", re.I)
CLOUD_SRC = re.compile(
    r"aws|cloudtrail|s3|ec2|azure|entra|gcp|google|gsuite|workspace|kubernetes|k8s|gke|eks|"
    r"o365|m365|office ?365|okta|github|saas|slack|jira|salesforce|cloudfront|lambda", re.I)


def surface(rule):
    """endpoint / cloud / mixed, from the upstream rule's own data sources."""
    blob = " ".join(rule.get("src") or []) + " " + (rule.get("name") or "")
    e, c = bool(ENDPOINT_SRC.search(blob)), bool(CLOUD_SRC.search(blob))
    if e and not c:
        return "endpoint"
    if c and not e:
        return "cloud"
    if e and c:
        return "mixed"
    return "unknown"


PRIORITY = ["convert", "non-endpoint-surface", "no-detection-strategy", "unresolved-id", "blocked-telemetry",
            "out-of-scope", "skipped", "parent", "covered"]


def get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "huntgraph-tracker"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")


def tree(repo, branch):
    u = "https://api.github.com/repos/%s/git/trees/%s?recursive=1" % (repo, branch)
    return json.loads(get(u)).get("tree", [])


def fetch_inventory():
    inv = {"splunk": [], "elastic": []}
    sp = [x["path"] for x in tree("splunk/security_content", "develop")
          if x["path"].startswith("detections/") and x["path"].endswith(".yml")
          and "/deprecated/" not in x["path"]]

    def sf(p):
        try:
            d = yaml.safe_load(get(SPLUNK + p)) or {}
            return {"path": p, "name": d.get("name"), "tech": d.get("mitre_attack_id") or [],
                    "type": d.get("type"), "src": d.get("data_source") or []}
        except Exception as exc:
            return {"path": p, "error": str(exc)[:60]}

    with cf.ThreadPoolExecutor(16) as ex:
        inv["splunk"] = list(ex.map(sf, sp))

    el = [x["path"] for x in tree("elastic/detection-rules", "main")
          if x["path"].startswith("rules/") and x["path"].endswith(".toml")
          and "_deprecated" not in x["path"]]

    def ef(p):
        try:
            raw = get(ELASTIC + p)
            nm = re.search(r'^name\s*=\s*"(.*?)"', raw, re.M)
            lg = re.search(r'^language\s*=\s*"([^"]+)"', raw, re.M)
            idx = re.search(r'^index\s*=\s*\[(.*?)\]', raw, re.M | re.S)
            return {"path": p, "name": nm.group(1) if nm else None,
                    "tech": sorted(set(re.findall(r'^id\s*=\s*"(T\d{4}(?:\.\d{3})?)"', raw, re.M))),
                    "type": lg.group(1) if lg else None,
                    "src": re.findall(r'"([^"]+)"', idx.group(1)) if idx else []}
        except Exception as exc:
            return {"path": p, "error": str(exc)[:60]}

    with cf.ThreadPoolExecutor(16) as ex:
        inv["elastic"] = list(ex.map(ef, el))
    return inv


def load_context():
    covered = set()
    for p in glob.glob(os.path.join(ROOT, "hunt", "*", "T*", "**", "*.yaml"), recursive=True):
        d = yaml.safe_load(open(p))
        covered |= set(d["mitre"].get("techniques") or [])
        covered |= set(d["mitre"].get("sub_techniques") or [])

    info = {}
    with open(os.path.join(ROOT, "coverage.csv")) as fh:
        for r in csv.DictReader(fh):
            tid = (r.get("subtechnique_id") or "").strip() or (r.get("technique_id") or "").strip()
            if not tid:
                continue
            e = info.setdefault(tid, {"status": set(), "plat": set(), "missing": set()})
            e["status"].add(r.get("status"))
            for p in (r.get("platforms") or "").replace(";", ",").split(","):
                if p.strip():
                    e["plat"].add(p.strip())
            for m in (r.get("data_components_missing") or "").replace(";", ",").split(","):
                if m.strip():
                    e["missing"].add(m.strip())
    return covered, info


def classifier(covered, info, atk):
    byid = getattr(atk, "by_attack_id", {})
    cache = {}

    def has_strategy(t):
        if t not in cache:
            obj = byid.get(t) if isinstance(byid, dict) else None
            try:
                cache[t] = bool(obj and list(atk.detection_strategies(obj)))
            except Exception:
                cache[t] = False
        return cache[t]

    def classify(t):
        if t in covered:
            return "covered"
        e = info.get(t)
        if not e:
            return "unresolved-id"
        s = e["status"]
        if "not-covered" in s:
            if not (e["plat"] & ENDPOINT):
                return "out-of-scope"
            if e["missing"]:
                return "blocked-telemetry"
            return "convert" if has_strategy(t) else "no-detection-strategy"
        for k in ("blocked-telemetry", "out-of-scope", "skipped", "parent", "covered"):
            if k in s:
                return k
        return "unresolved-id"
    return classify


def decide(rule, classify):
    if rule.get("error"):
        return "fetch-error", []
    tech = rule.get("tech") or []
    if not tech:
        return "staged-unmapped", []
    cls = {t: classify(t) for t in tech}
    for p in PRIORITY:
        hit = [t for t in tech if cls[t] == p]
        if hit:
            # only a rule that demonstrably reads endpoint telemetry converts.
            # "unknown" means the upstream rule declares no data source, which is
            # not evidence of endpoint visibility — GitHub, mail-gateway and ML
            # rules all land there.
            if p == "convert" and surface(rule) != "endpoint":
                return "non-endpoint-surface", hit
            return p, hit
    return "covered", tech


def write_tracker(path, title, source_url, rows, base_url):
    counts = collections.Counter(r["decision"] for r in rows)
    done = sum(1 for r in rows if r.get("template"))
    queue = counts.get("convert", 0)
    out = []
    out.append("# %s\n" % title)
    out.append("Upstream: %s\n" % source_url)
    out.append("Generated by `python3 tools/track_sources.py` — regenerate, never hand-edit.\n")
    out.append("**%d rules tracked · %d queued for conversion · %d converted · %d remaining**\n"
               % (len(rows), queue, done, queue - done))
    out.append("## Routing\n")
    out.append("| Decision | Rules | Why |")
    out.append("|---|---:|---|")
    for d in PRIORITY + ["staged-unmapped", "fetch-error"]:
        if counts.get(d):
            out.append("| `%s` | %d | %s |" % (d, counts[d], REASON.get(d, "")))
    out.append("")
    order = ["convert", "staged-unmapped"] + [d for d in PRIORITY if d != "convert"] + ["fetch-error"]
    for d in order:
        sel = [r for r in rows if r["decision"] == d]
        if not sel:
            continue
        out.append("## %s — %d\n" % (d, len(sel)))
        out.append("_%s_\n" % REASON.get(d, ""))
        if d in ("convert", "staged-unmapped"):
            out.append("| Status | Rule | Technique | Template | Source |")
            out.append("|---|---|---|---|---|")
            for r in sorted(sel, key=lambda x: (x.get("drivers") or [""])[0] + (x.get("name") or "")):
                mark = "done" if r.get("template") else "todo"
                out.append("| %s | %s | %s | %s | [src](%s) |" % (
                    mark, (r.get("name") or r["path"])[:70],
                    ", ".join(r.get("drivers") or []) or "—",
                    r.get("template") or "—", base_url + r["path"]))
        else:
            out.append("| Rule | Technique |")
            out.append("|---|---|")
            for r in sorted(sel, key=lambda x: (x.get("name") or x["path"])):
                out.append("| %s | %s |" % ((r.get("name") or r["path"])[:80],
                                            ", ".join(r.get("tech") or []) or "—"))
        out.append("")
    open(path, "w").write("\n".join(out))
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory")
    a = ap.parse_args()
    inv = json.load(open(a.inventory)) if a.inventory and os.path.exists(a.inventory) else fetch_inventory()
    if a.inventory and not os.path.exists(a.inventory):
        json.dump(inv, open(a.inventory, "w"))

    covered, info = load_context()
    atk = V.Attack(V.load_bundle())
    classify = classifier(covered, info, atk)

    # a template records which upstream rule it came from, via info.references
    origin = {}
    for p in glob.glob(os.path.join(ROOT, "hunt", "*", "T*", "**", "*.yaml"), recursive=True):
        d = yaml.safe_load(open(p))
        for ref in (d.get("info", {}) or {}).get("references", []) or []:
            origin[ref.rstrip("/")] = os.path.relpath(p, ROOT)

    tally = {}
    for src, base in (("splunk", SPLUNK), ("elastic", ELASTIC)):
        rows = []
        for r in inv[src]:
            dec, drivers = decide(r, classify)
            rows.append({**r, "decision": dec, "drivers": drivers,
                         "template": origin.get((base + r["path"]).rstrip("/"))})
        name = "splunk_tracker.md" if src == "splunk" else "elk_tracker.md"
        title = ("Splunk detection tracker" if src == "splunk" else "Elastic (ELK) detection tracker")
        url = ("https://research.splunk.com/detections/" if src == "splunk"
               else "https://elastic.github.io/detection-rules-explorer/")
        tally[src] = write_tracker(os.path.join(ROOT, name), title, url, rows, base)
        staged = [r for r in rows if r["decision"] == "staged-unmapped"]
        if staged:
            d = os.path.join(ROOT, "unclassified-threat-check")
            os.makedirs(d, exist_ok=True)
            f = os.path.join(d, "%s-unmapped.md" % src)
            out = ["# Unmapped %s rules\n" % src,
                   "Upstream rules carrying no ATT&CK mapping. Staged for triage — these are",
                   "**not** detection templates and are not validated: the schema requires a",
                   "MITRE id in every `id`, so they cannot be filed as templates under `hunt/`.\n",
                   "Generated by `python3 tools/track_sources.py` — regenerate, never hand-edit.\n",
                   "%d rules.\n" % len(staged), "| Rule | Upstream |", "|---|---|"]
            for r in sorted(staged, key=lambda x: (x.get("name") or x["path"])):
                out.append("| %s | [src](%s) |" % ((r.get("name") or r["path"])[:80], base + r["path"]))
            open(f, "w").write("\n".join(out) + "\n")
        print("wrote %-18s %d rules  convert=%d staged=%d"
              % (name, len(rows), tally[src].get("convert", 0), tally[src].get("staged-unmapped", 0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
