#!/usr/bin/env python3
"""Import SigmaHQ threat-hunting rules into hunt/<category>/sigma/, and write sigma_tracker.md.

    python3 tools/import_sigma.py                      # the pinned Sigma commit
    python3 tools/import_sigma.py --ref <sha>          # re-pin to another commit

Rules are copied byte-for-byte from the pinned commit. They are upstream material, not
huntgraph templates: validate.py skips every sigma/ folder, and nothing here is converted.
Both the rule tree and the tracker are generated — rerun this, never hand-edit them.

Categories follow Elastic's prebuilt-rule domains. A rule is filed by the telemetry it
reads (its Sigma logsource), not by the technique it maps to: a Windows host log is
Endpoint whatever the technique, and Identity means an identity provider, not a
workstation's own account events.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import json
import os
import re
import shutil
import sys
import urllib.request

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HUNT = os.path.join(ROOT, "hunt")
TRACKER = os.path.join(ROOT, "sigma_tracker.md")

REPO = "SigmaHQ/sigma"
REF = "2e8fd89f82d9104c1b30321a307254ddeea17de2"
SOURCE_DIR = "rules-threat-hunting/windows"

ELASTIC = "https://www.elastic.co/docs/reference/security/prebuilt-rules#"
CATEGORIES = [  # (folder, display name, what belongs there)
    ("cloud", "Cloud", "cloud provider control planes and services (AWS, Azure, GCP)"),
    ("containers", "Containers", "container runtimes and images"),
    ("email", "Email", "mail gateways and mailbox activity"),
    ("endpoint", "Endpoint", "host telemetry from Windows, Linux and macOS"),
    ("identity", "Identity", "identity providers and directory services (Okta, Entra ID)"),
    ("kubernetes", "Kubernetes", "Kubernetes API and cluster audit"),
    ("llm", "LLM", "large-language-model applications and gateways"),
    ("network", "Network", "network devices, flows and packet data"),
    ("saas", "SaaS", "software-as-a-service applications"),
    ("unspecified", "Unspecified", "rules whose telemetry fits no other domain"),
    ("web", "Web", "web servers, proxies and web application logs"),
]
NAME = {c[0]: c[1] for c in CATEGORIES}

HOST_PRODUCTS = {"windows", "linux", "macos"}
PRODUCT_CATEGORY = {
    "aws": "cloud", "azure": "cloud", "gcp": "cloud",
    "okta": "identity", "onelogin": "identity", "entra": "identity",
    "kubernetes": "kubernetes",
    "github": "saas", "m365": "saas", "google_workspace": "saas",
    "zeek": "network", "cisco": "network", "fortinet": "network",
}
LOGSOURCE_CATEGORY = {"webserver": "web", "proxy": "web", "firewall": "network", "dns": "network"}


def get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "huntgraph-sigma-import"})
    return urllib.request.urlopen(req, timeout=30).read().decode("utf-8")


def categorise(rule: dict) -> str:
    ls = rule.get("logsource") or {}
    product = (ls.get("product") or "").lower()
    if product in HOST_PRODUCTS:
        return "endpoint"
    if product in PRODUCT_CATEGORY:
        return PRODUCT_CATEGORY[product]
    return LOGSOURCE_CATEGORY.get((ls.get("category") or "").lower(), "unspecified")


def techniques(rule: dict) -> list[str]:
    tags = [str(t).lower() for t in rule.get("tags") or []]
    return sorted({t[len("attack."):].upper() for t in tags if re.match(r"attack\.t\d{4}", t)})


def cell(text: str) -> str:
    return " ".join(str(text or "").split()).replace("|", "\\|")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", default=REF, help="Sigma commit to import from")
    ref = ap.parse_args().ref

    tree = json.loads(get("https://api.github.com/repos/%s/git/trees/%s?recursive=1" % (REPO, ref)))
    if tree.get("truncated"):
        sys.exit("git tree listing was truncated; cannot trust it to be complete")
    paths = sorted(x["path"] for x in tree["tree"]
                   if x["path"].startswith(SOURCE_DIR + "/") and x["path"].endswith(".yml"))
    raw_base = "https://raw.githubusercontent.com/%s/%s/" % (REPO, ref)
    with cf.ThreadPoolExecutor(16) as ex:
        bodies = dict(zip(paths, ex.map(lambda p: get(raw_base + p), paths)))

    # rebuild only what this tool owns, so a re-pin cannot leave stale rules behind
    for folder, _, _ in CATEGORIES:
        shutil.rmtree(os.path.join(HUNT, folder, "sigma"), ignore_errors=True)

    rows, counts = [], collections.Counter()
    for p in paths:
        rule = yaml.safe_load(bodies[p]) or {}
        cat = categorise(rule)
        rel = os.path.join("hunt", cat, "sigma", os.path.relpath(p, "rules-threat-hunting"))
        os.makedirs(os.path.dirname(os.path.join(ROOT, rel)), exist_ok=True)
        with open(os.path.join(ROOT, rel), "w", encoding="utf-8", newline="") as fh:
            fh.write(bodies[p])
        counts[cat] += 1
        rows.append((cat, techniques(rule), rule.get("title") or os.path.basename(p),
                     rule.get("description"), rel,
                     "https://github.com/%s/blob/%s/%s" % (REPO, ref, p)))

    for folder, name, meaning in CATEGORIES:
        d = os.path.join(HUNT, folder)
        os.makedirs(d, exist_ok=True)
        templates = sum(1 for dp, dirs, fs in os.walk(d) if "sigma" not in dp.split(os.sep)
                        for f in fs if f.endswith(".yaml"))
        with open(os.path.join(d, "README.md"), "w") as fh:
            fh.write("# %s\n\nHunts about %s — category as defined by Elastic's "
                     "[prebuilt rules](%s%s).\n\n" % (name, meaning, ELASTIC, folder))
            fh.write("| Here | Count | What it is |\n|---|---:|---|\n")
            fh.write("| `T####-…/` | %d | huntgraph templates, validated by `tools/validate.py` |\n"
                     % templates)
            fh.write("| `sigma/` | %d | SigmaHQ threat-hunting rules, unmodified, Detection Rule "
                     "License 1.1 — reference only |\n\n" % counts[folder])
            fh.write("See [stats.md](../../stats.md) and [sigma_tracker.md](../../sigma_tracker.md). "
                     "Generated by `python3 tools/import_sigma.py` — regenerate, never hand-edit.\n")

    rows.sort(key=lambda r: (r[0], r[1][0] if r[1] else "~", r[2].lower()))
    out = ["# Sigma threat-hunting rule tracker\n",
           "Upstream: [%s/%s](https://github.com/%s/tree/%s/%s) at commit `%s`, released under the "
           "[Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License).\n"
           % (REPO, SOURCE_DIR, REPO, ref, SOURCE_DIR, ref[:7]),
           "Rules are stored unmodified under `hunt/<category>/sigma/`, beside the templates for "
           "the same category. They are upstream material, not huntgraph templates, and are not "
           "validated.\n",
           "Generated by `python3 tools/import_sigma.py` — regenerate, never hand-edit.\n",
           "## By category\n", "| Category | Rules |", "|---|---:|"]
    out += ["| [%s](hunt/%s/) | %d |" % (name, folder, counts[folder]) for folder, name, _ in CATEGORIES]
    out += ["| **Total** | **%d** |" % len(rows), "", "## Rules\n",
            "| Category | TTP | Rule | Description | Path |", "|---|---|---|---|---|"]
    for cat, ttp, title, desc, rel, url in rows:
        out.append("| %s | %s | [%s](%s) | %s | [%s](%s) |"
                   % (NAME[cat], ", ".join(ttp) or "—", cell(title), url, cell(desc), rel, rel))
    with open(TRACKER, "w") as fh:
        fh.write("\n".join(out) + "\n")

    print("imported %d rules from %s@%s" % (len(rows), REPO, ref[:7]))
    for folder, name, _ in CATEGORIES:
        print("   %-12s %d" % (name, counts[folder]))
    print("without an ATT&CK technique: %d" % sum(1 for r in rows if not r[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
