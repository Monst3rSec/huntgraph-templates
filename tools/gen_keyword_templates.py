#!/usr/bin/env python3
"""Generate hunt/keyword/ templates from mthcht/ThreatHunting-Keywords tools/*.csv.

One CSV is one offensive/greyware tool; one tool becomes one template whose CQL
cases return raw events whose command line (or written filename) matches any of
the tool's keywords. No groupBy, no select, no sort -- the agent gets the events.

CrowdStrike NG-SIEM caps a query at 30,000 characters, so a tool whose keyword
alternation does not fit is split across -part2, -part3, ... templates.

hunt/keyword/ is deliberately outside the validated corpus: these hunts are
anchored on a tool name, not on a MITRE technique, so they cannot satisfy L5's
hunt/<category>/<Txxxx-slug>/ layout. The mitre: block below carries the
upstream CSV's own ATT&CK mapping verbatim -- it is upstream metadata, not a
fact this repo has verified against the STIX bundle.

Usage:
    python3 tools/gen_keyword_templates.py --source <path to ThreatHunting-Keywords>
"""
import argparse
import csv
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "hunt", "keyword")

RAW_BASE = ("https://raw.githubusercontent.com/mthcht/ThreatHunting-Keywords/"
            "main/tools")

# CrowdStrike NG-SIEM hard limit; leave room for the event-type line and pipes.
QUERY_LIMIT = 30000
ALT_BUDGET = 28500

WRAP = ".{0,1000}"

# Listed in requires.logs as where the fields come from. The queries deliberately
# carry no #event_simpleName filter: a keyword is worth seeing on whatever event
# carries it, so the sweep is scoped by field alone.
PROC_EVENTS = "ProcessRollup2|SyntheticProcessRollup2"
FILE_EVENTS = "NewScriptWritten|PeFileWritten"

FILE_EXT = re.compile(
    r"\\\.(exe|dll|sys|ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|hta|py|pyc|jar|"
    r"msi|scr|com|cpl|ocx|lnk|iso|img|vhd|zip|7z|rar|cab|gz|tgz|bin|dat|pdb|"
    r"so|elf|sh|aspx?|php\d?|jsp)\b", re.I)

SAFE_SLUG = re.compile(r"[^a-z0-9]+")


def slug(text: str) -> str:
    s = SAFE_SLUG.sub("-", text.lower()).strip("-")
    return s or "unnamed"


def core_regex(raw: str) -> str:
    """Strip upstream's .{0,1000} padding down to the distinguishing substring."""
    s = (raw or "").strip()
    if not s:
        return ""
    if s.startswith(WRAP):
        s = s[len(WRAP):]
    if s.endswith(WRAP):
        s = s[:-len(WRAP)]
    s = s.strip()
    # a bare wildcard would match every event; it is not a keyword
    if not s or s in (".*", ".+", WRAP):
        return ""
    if "\n" in s or "\r" in s:
        return ""
    # CQL writes regexes as /.../ so an unescaped slash has to be escaped
    s = re.sub(r"(?<!\\)/", r"\\/", s)
    return s


def core_from_glob(kw: str) -> str:
    """Build a regex from the raw `keyword` glob.

    Upstream normally ships metadata_keyword_regex; a handful of CSVs have a
    header that omits it, and for those the glob is all there is.
    """
    s = (kw or "").strip().strip("*")
    if not s or "\n" in s or "\r" in s:
        return ""
    s = WRAP.join(re.escape(part) for part in s.split("*"))
    return re.sub(r"(?<!\\)/", r"\\/", s)


def severity_of(score: str) -> str:
    try:
        n = int(float(score))
    except (TypeError, ValueError):
        return "medium"
    if n >= 9:
        return "critical"
    if n >= 7:
        return "high"
    if n >= 4:
        return "medium"
    return "low"


def chunk_alternatives(alts: list[str], budget: int) -> list[list[str]]:
    """Pack alternatives into groups whose joined length stays under budget."""
    groups, cur, size = [], [], 0
    for a in alts:
        add = len(a) + (1 if cur else 0)
        if cur and size + add > budget:
            groups.append(cur)
            cur, size = [a], len(a)
        else:
            cur.append(a)
            size += add
    if cur:
        groups.append(cur)
    return groups or [[]]


def block(text: str, indent: int) -> str:
    """Render a paragraph as a folded scalar body at the given indent."""
    pad = " " * indent
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > 88:
            lines.append(pad + cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(pad + cur)
    return "\n".join(lines)


def yq(text: str) -> str:
    """Quote a scalar for YAML."""
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"') + '"'


def read_tool(path: str) -> dict | None:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    rows = [r for r in rows
            if r.get("metadata_keyword_regex") or r.get("keyword")]
    if not rows:
        return None
    meta = rows[0]

    def regex_of(r):
        return (core_regex(r.get("metadata_keyword_regex", ""))
                or core_from_glob(r.get("keyword", "")))

    # Every row of the `keyword` column is carried. Duplicates are dropped on two
    # keys -- the raw glob and the regex it compiles to -- because upstream repeats
    # a keyword across rows and two different globs can compile to one regex.
    seen_glob: set[str] = set()
    seen_core: set[str] = set()
    alts: list[str] = []
    dropped_empty = dupes = 0
    for r in rows:
        # Not stripped: upstream encodes a keyword's trailing spaces in the regex
        # ("...VeeamDeploySvc.{0,1000}\\s\\s\\s\\s"), so two globs that differ only
        # by surrounding whitespace are two different regexes, not a duplicate.
        glob_key = (r.get("keyword") or "").lower()
        if glob_key and glob_key in seen_glob:
            dupes += 1
            continue
        rx = regex_of(r)
        if not rx:
            dropped_empty += 1
            continue
        core_key = rx.lower()
        if core_key in seen_core:
            dupes += 1
            if glob_key:
                seen_glob.add(glob_key)
            continue
        if glob_key:
            seen_glob.add(glob_key)
        seen_core.add(core_key)
        # a bare | inside a keyword would rebind the surrounding alternation
        alts.append(alternative(rx))
    if not alts:
        return None
    alts.sort(key=lambda s: (s.lower(), s))

    def split(vals):
        out = []
        for v in (vals or "").split(" - "):
            v = v.strip()
            if v and v.upper() != "N/A" and v not in out:
                out.append(v)
        return out

    return {
        "tool": meta.get("metadata_tool") or os.path.basename(path)[:-4],
        "description": (meta.get("metadata_description") or "").strip(),
        "category": (meta.get("metadata_category") or "").strip(),
        "keyword_type": (meta.get("metadata_keyword_type") or "").strip(),
        "link": (meta.get("metadata_link") or "").strip(),
        "severity": severity_of(meta.get("metadata_severity_score")),
        "techniques": [t for t in split(meta.get("metadata_tool_techniques"))
                       if re.fullmatch(r"T\d{4}", t)],
        "sub_techniques": [t for t in split(meta.get("metadata_tool_techniques"))
                           if re.fullmatch(r"T\d{4}\.\d{3}", t)],
        "tactics": [t for t in split(meta.get("metadata_tool_tactics"))
                    if re.fullmatch(r"TA\d{4}", t)],
        "malwares": split(meta.get("metadata_malwares_name")),
        "groups": split(meta.get("metadata_groups_name")),
        "alts": alts,
        "dupes": dupes,
        "dropped_empty": dropped_empty,
        "total_rows": len(rows),
    }


def render(t: dict, bucket: str, csv_name: str, part: int, parts: int,
           alts: list[str]) -> str:
    tool = t["tool"]
    base = slug(tool)
    suffix = "" if part == 1 else "-part%d" % part
    tid = "hg-any-keyword-%s%s" % (base, suffix)
    part_note = "" if parts == 1 else " (part %d of %d)" % (part, parts)

    proc_alt = "|".join(alts)
    file_alts = [a for a in alts if FILE_EXT.search(a)]
    file_alt = "|".join(file_alts)

    upstream = "%s/%s/%s" % (RAW_BASE, bucket, csv_name)
    refs = [upstream]
    if t["link"].startswith("https://") and t["link"] not in refs:
        refs.append(t["link"])

    tags = ["keyword-hunt", "threathunting-keywords", slug(bucket)]
    for extra in (t["keyword_type"], t["category"]):
        s = slug(extra) if extra and extra.upper() != "N/A" else ""
        if s and s not in tags:
            tags.append(s)
    for g in t["groups"][:4]:
        s = slug(g)
        if s and s not in tags:
            tags.append(s)

    desc = (
        "%s. Keyword sweep for the tool %s, built from the %d keyword%s "
        "mthcht/ThreatHunting-Keywords publishes for it%s. The hunt is the tool's "
        "own vocabulary: command switches, function names, filenames and strings "
        "that the tool emits and that nothing else on the estate should. The query "
        "returns the raw matching events rather than a count, so the agent can read "
        "the full command line, the user and the host for itself."
        % (t["description"] or tool, tool, len(t["alts"]),
           "" if len(t["alts"]) == 1 else "s", part_note)
    )
    desc += (" Every distinct keyword upstream publishes for the tool is carried,"
             " whether or not upstream marks it endpoint-detectable.")
    if t["dupes"]:
        desc += (" %d upstream row%s a keyword already in the set and %s dropped."
                 % (t["dupes"], " repeated" if t["dupes"] == 1 else "s repeated",
                    "was" if t["dupes"] == 1 else "were"))

    out = []
    w = out.append
    w("# GENERATED by tools/gen_keyword_templates.py -- do not hand-edit.")
    w("# Source: %s" % upstream)
    w("# hunt/keyword/ sits outside the validated corpus; see hunt/keyword/README.md.")
    w("type: detection")
    w("")
    w("id: %s" % tid)
    w("version: 1.0.0")
    w("")
    w("info:")
    w("  name: %s" % yq(("%s tool keywords observed on an endpoint%s"
                         % (tool, part_note))[:120]))
    w("  description: >-")
    w(block(desc, 4))
    w("  severity: %s" % t["severity"])
    w("  author: huntgraph")
    w("  tags:")
    for tg in tags:
        w("    - %s" % tg)
    w("  references:")
    for r in refs:
        w("    - %s" % r)
    w("")
    w("# Upstream metadata, carried verbatim from the CSV. NOT verified against the")
    w("# ATT&CK STIX bundle by tools/attack_extract.py, which is why this file is")
    w("# excluded from tools/validate.py.")
    w("mitre:")
    w("  tactics:%s" % ("" if t["tactics"] else " []"))
    for x in t["tactics"]:
        w("    - %s" % x)
    w("  techniques:%s" % ("" if t["techniques"] else " []"))
    for x in t["techniques"]:
        w("    - %s" % x)
    w("  sub_techniques:%s" % ("" if t["sub_techniques"] else " []"))
    for x in t["sub_techniques"]:
        w("    - %s" % x)
    w("  detection_strategies: []")
    w("  analytics: []")
    w("  platforms:")
    w("    - Windows")
    w("    - Linux")
    w("    - macOS")
    w("  data_sources:")
    w("    - CrowdStrike:Endpoint")
    w("  data_components:")
    w("    - Process Creation")
    w("    - File Creation")
    w("")
    w("hypothesis:")
    stmt = ("An adversary or an unsanctioned insider running %s on a managed host will "
            "leave the tool's own strings in process command lines and in the filenames "
            "it drops, because those strings are how the tool is invoked and what it "
            "installs; no unrelated software on the estate produces them." % tool)
    w("  statement: >-")
    w(block(stmt, 4))
    w("  attacker_behavior:")
    w("    - %s" % yq("Downloads or copies %s onto the host and invokes it from a shell." % tool))
    w("    - %s" % yq("Calls the tool's functions or switches, which appear verbatim in the command line."))
    w("    - %s" % yq("Drops the tool's modules, binaries or output files onto disk under their published names."))
    w("    - %s" % yq("Renames the binary while leaving the command switches and function names unchanged."))
    if t["groups"]:
        w("    - %s" % yq("Reported in use by %s." % ", ".join(t["groups"][:6])))
    if t["malwares"]:
        w("    - %s" % yq("Associated with %s." % ", ".join(t["malwares"][:6])))
    w("  legitimate_behavior:")
    w("    - %s" % yq("Administrators and red teams use %s under an approved engagement." % tool))
    w("    - %s" % yq("Security tooling scans, quarantines or unpacks a copy of the tool, echoing its name."))
    w("    - %s" % yq("Documentation, research notes or installer manifests mention the tool by name."))
    w("    - %s" % yq("A build or package pipeline mirrors the project for internal review."))
    w("  risk_indicator:")
    w("    - %s" % yq("The host is a workstation or server with no engineering or red-team role."))
    w("    - %s" % yq("The tool runs from a user-writable path such as Downloads, Temp or a public share."))
    w("    - %s" % yq("The invoking account is a service account or one that has never run tooling before."))
    w("    - %s" % yq("The run is a one-off with no change ticket, engagement window or ancestor that explains it."))
    w("")
    w("requires:")
    w("  platforms:")
    w("    - windows")
    w("    - linux")
    w("    - macos")
    w("  connectors:")
    w("    - crowdstrike-ngsiem")
    w("  logs:")
    w("    - source: process_creation")
    w("      connector: crowdstrike-ngsiem")
    w("      event_types:")
    for e in PROC_EVENTS.split("|"):
        w("        - %s" % e)
    w("      fields:")
    w("        agent_id: aid")
    w("        host: ComputerName")
    w("        user: UserName")
    w("        image_name: FileName")
    w("        image_path: ImageFileName")
    w("        command_line: CommandLine")
    w("        parent_process: ParentBaseFileName")
    if file_alts:
        w("    - source: file_creation")
        w("      connector: crowdstrike-ngsiem")
        w("      event_types:")
        for e in FILE_EVENTS.split("|"):
            w("        - %s" % e)
        w("      fields:")
        w("        agent_id: aid")
        w("        host: ComputerName")
        w("        file_path: TargetFileName")
        w("        writer_process_id: ContextProcessId")
    w("")
    w("query:")
    w("  - platform: crowdstrike")
    w("    language: cql")
    w("")
    w("    cases:")
    w("      - id: command-line-keywords%s" % ("" if part == 1 else "-part%d" % part))
    w("        name: %s" % yq(("%s keywords in a process command line%s" % (tool, part_note))))
    w("        purpose: >-")
    w(block("Return every process event whose command line carries any of this tool's "
            "%d keyword%s. Raw events, so the agent reads the host, the user, the parent "
            "and the full command line and decides for itself whether the run was "
            "sanctioned." % (len(alts), "" if len(alts) == 1 else "s"), 10))
    w("        query: |")
    w("          CommandLine=/(%s)/i" % proc_alt)
    w("        filters:")
    w("          include: []")
    w("          exclude:")
    w("            - %s" % yq("Hosts inside an approved red-team or penetration-test engagement window"))
    w("            - %s" % yq("Command lines belonging to the endpoint security product scanning or quarantining a copy of the tool"))
    w("        baseline:")
    w("          required: true")
    w("          window: 90d")
    w("          compare:")
    w("            - host")
    w("            - user")
    w("            - command_line")
    if file_alts:
        w("")
        w("      - id: dropped-tool-files%s" % ("" if part == 1 else "-part%d" % part))
        w("        name: %s" % yq(("%s files written to disk%s" % (tool, part_note))))
        w("        purpose: >-")
        w(block("Return the file-write events whose target filename matches the subset of "
                "this tool's keywords that name a file on disk (%d of %d). This catches "
                "the tool at staging, before anyone runs it, and catches it when the "
                "operator renames the launcher but ships the modules unchanged."
                % (len(file_alts), len(alts)), 10))
        w("        query: |")
        w("          TargetFileName=/(%s)/i" % file_alt)
        w("        filters:")
        w("          include: []")
        w("          exclude:")
        w("            - %s" % yq("ContextProcessId of the endpoint security product writing a quarantined copy"))
        w("        baseline:")
        w("          required: true")
        w("          window: 90d")
        w("          compare:")
        w("            - host")
        w("            - path")
    w("")
    w("evidence:")
    w("  required:")
    w("    - id: tool_keyword_on_command_line")
    w("      name: %s" % yq("%s keyword in a command line" % tool))
    w("      description: >-")
    w(block("A process was created whose command line contains a string published as a "
            "keyword for %s -- a switch, a function name, a module name or a literal the "
            "tool emits. The string is specific to the tool, so its presence means a copy "
            "of the tool was invoked on this host." % tool, 8))
    w("      source: process_creation")
    w("      field: command_line")
    w("      indicates: offensive_tool_execution")
    w("")
    w("  supporting:")
    w("    - id: tool_file_on_disk")
    w("      name: %s" % yq("%s file written to disk" % tool))
    w("      description: >-")
    w(block("A file whose name matches one of the tool's published artefacts was created "
            "on the host, which places a copy of the tool on disk rather than only in a "
            "transient command line.", 8))
    w("      source: file_creation")
    w("      field: file_path")
    w("      indicates: tooling_staged_on_host")
    w("    - id: user_writable_path")
    w("      name: Tool run from a user-writable directory")
    w("      description: >-")
    w(block("The image path or the referenced file sits under Downloads, Temp, AppData, "
            "a profile directory or a public share, which is where tooling is dropped "
            "rather than where managed software is installed.", 8))
    w("      source: process_creation")
    w("      field: image_path")
    w("      indicates: unmanaged_binary_location")
    w("    - id: first_time_for_host")
    w("      name: First occurrence on this host")
    w("      description: >-")
    w(block("No command line carrying this tool's keywords has been seen on the host "
            "during the baseline window, so the run is new rather than part of a "
            "standing workflow.", 8))
    w("      source: baseline")
    w("      field: ComputerName")
    w("      indicates: unusual_activity_for_host")
    w("    - id: unexpected_account")
    w("      name: Account not associated with tooling")
    w("      description: >-")
    w(block("The invoking account is a service account, a shared account or a user whose "
            "role does not include security testing or system engineering.", 8))
    w("      source: process_creation")
    w("      field: user")
    w("      indicates: unexpected_actor")
    w("    - id: interactive_parent")
    w("      name: Launched from an interactive shell")
    w("      description: >-")
    w(block("The parent process is a shell, a remote-management agent or a script host "
            "rather than an installer or a management platform, which is hands-on use "
            "rather than a packaged deployment.", 8))
    w("      source: process_creation")
    w("      field: parent_process")
    w("      indicates: hands_on_keyboard_activity")
    w("")
    w("  contradicting:")
    w("    - id: sanctioned_engagement")
    w("      name: Approved testing engagement")
    w("      description: >-")
    w(block("The host, account and time fall inside a recorded red-team or penetration-test "
            "engagement, which authorises exactly this tooling.", 8))
    w("      source: asset_inventory")
    w("      field: ComputerName")
    w("      indicates: legitimate_enterprise_activity")
    w("    - id: security_product_handling")
    w("      name: Security product handling a sample")
    w("      description: >-")
    w(block("The command line or the file write belongs to the endpoint security product, "
            "a sandbox or an archiver scanning, quarantining or unpacking a copy of the "
            "tool, which echoes its name without running it.", 8))
    w("      source: process_creation")
    w("      field: parent_process")
    w("      indicates: security_tooling_activity")
    w("    - id: routine_for_this_operator")
    w("      name: Routine for this host and account")
    w("      description: >-")
    w(block("The same account has run the same tool on the same host repeatedly across the "
            "baseline window with a stable command shape, matching a standing "
            "administrative or research workflow.", 8))
    w("      source: baseline")
    w("      field: CommandLine")
    w("      indicates: established_workflow")
    w("")
    w("  risk_logic:")
    w("    required:")
    w("      - tool_keyword_on_command_line")
    w("")
    w("    supporting:")
    w("      any:")
    w("        - tool_file_on_disk")
    w("        - user_writable_path")
    w("        - first_time_for_host")
    w("        - unexpected_account")
    w("        - interactive_parent")
    w("      all:")
    w("        - first_time_for_host")
    w("        - user_writable_path")
    w("")
    w("    contradicting:")
    w("      any:")
    w("        - sanctioned_engagement")
    w("        - security_product_handling")
    w("        - routine_for_this_operator")
    w("      all: []")
    w("")
    w("  verdict:")
    w("    low_risk_when:")
    w("      - tool_keyword_on_command_line")
    w("      - sanctioned_engagement")
    w("      - security_product_handling")
    w("      - routine_for_this_operator")
    w("    suspicious_when:")
    w("      - tool_keyword_on_command_line")
    w("      - first_time_for_host")
    w("    high_risk_when:")
    w("      - tool_keyword_on_command_line")
    w("      - user_writable_path")
    w("      - first_time_for_host")
    w("      - unexpected_account")
    w("")
    w("  false_positive:")
    w("    - condition: %s" % yq("An approved red-team or penetration-test engagement is running."))
    w("      explanation: >-")
    w(block("Testers run exactly this tooling by design, reproducing every piece of "
            "evidence here. The engagement record names the host, the account and the "
            "window; matches outside it are the ones worth reading.", 8))
    w("    - condition: %s" % yq("The endpoint security product scans or quarantines a copy of the tool."))
    w("      explanation: >-")
    w(block("Scanners and archivers put the sample's path on their own command line and "
            "write quarantined copies to disk, so the tool's name appears without the "
            "tool ever executing. The process is the security product itself.", 8))
    w("    - condition: %s" % yq("An engineer researches or documents the tool."))
    w("      explanation: >-")
    w(block("Cloning the project, reading its source or writing about it puts the tool's "
            "filenames and function names into command lines and onto disk without any "
            "of it being run against the estate. The activity clusters on a developer "
            "workstation and stops at fetch and read.", 8))
    w("    - condition: %s" % yq("A legitimate product ships a file or switch with the same name."))
    w("      explanation: >-")
    w(block("Some keywords are generic enough to collide with unrelated software, "
            "especially the shorter filenames. A collision repeats at volume across many "
            "hosts with a stable parent, where real tool use is sparse and varied.", 8))
    return "\n".join(out) + "\n"


def alternative(core: str) -> str:
    """How a core regex is written into the alternation."""
    return "(?:%s)" % core if "|" in core else core


def verify(src: str) -> int:
    """Cross-check the generated queries against the CSVs' own `keyword` column.

    Every keyword upstream publishes must appear, verbatim, in the query of the
    template generated for its tool. Reports anything that did not make it.
    """
    # (bucket, tool slug) -> all query text written for that tool, parts joined
    queries: dict[tuple[str, str], str] = {}
    for bucket in sorted(os.listdir(OUT_DIR)):
        bdir = os.path.join(OUT_DIR, bucket)
        if not os.path.isdir(bdir):
            continue
        for name in sorted(os.listdir(bdir)):
            if not name.endswith(".yaml"):
                continue
            base = re.sub(r"-part\d+$", "", name[:-5])
            with open(os.path.join(bdir, name), encoding="utf-8") as fh:
                text = fh.read().lower()
            queries[(bucket, base)] = queries.get((bucket, base), "") + text

    # One distinct keyword is one thing to cover. Upstream sometimes ships two rows
    # with the same keyword and different regexes; the keyword is covered as soon
    # as one of them reaches the query, and carrying both would be the duplicate.
    wanted: dict[tuple[str, str, str], list[str]] = {}
    for bucket in sorted(os.listdir(src)):
        bdir = os.path.join(src, bucket)
        if not os.path.isdir(bdir):
            continue
        for name in sorted(os.listdir(bdir)):
            if not name.endswith(".csv"):
                continue
            with open(os.path.join(bdir, name), newline="",
                      encoding="utf-8-sig") as fh:
                rows = list(csv.DictReader(fh))
            for r in rows:
                kw = r.get("keyword")
                if not kw:
                    continue
                tool = r.get("metadata_tool") or name[:-4]
                key = (slug(bucket), slug(tool), kw)
                core = (core_regex(r.get("metadata_keyword_regex", ""))
                        or core_from_glob(kw))
                wanted.setdefault(key, [])
                if core:
                    wanted[key].append(alternative(core).lower())

    checked = missing = empty = 0
    gaps: list[str] = []
    for (bucket, tool, kw), cores in sorted(wanted.items()):
        if not cores:
            empty += 1
            gaps.append("%s/%s  %r -> no usable regex" % (bucket, tool, kw[:70]))
            continue
        checked += 1
        hay = queries.get((bucket, tool))
        if hay is None:
            missing += 1
            gaps.append("%s  no template for tool %r" % (bucket, tool))
        elif not any(c in hay for c in cores):
            missing += 1
            gaps.append("%s/%s  %r not in query" % (bucket, tool, kw[:70]))

    print("distinct keywords: %d" % checked)
    print("unusable keyword : %d (empty or wildcard-only after stripping)" % empty)
    print("missing from query: %d" % missing)
    for g in gaps[:20]:
        print("   %s" % g)
    if len(gaps) > 20:
        print("   ... %d more" % (len(gaps) - 20))
    return 1 if missing else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", required=True,
                    help="checkout of mthcht/ThreatHunting-Keywords")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the keyword-coverage cross-check")
    args = ap.parse_args()

    src = os.path.join(args.source, "tools")
    if not os.path.isdir(src):
        print("no tools/ under %s" % args.source, file=sys.stderr)
        return 2

    written = tools = skipped = split_tools = merged = 0
    for bucket in sorted(os.listdir(src)):
        bdir = os.path.join(src, bucket)
        if not os.path.isdir(bdir):
            continue
        odir = os.path.join(OUT_DIR, slug(bucket))
        os.makedirs(odir, exist_ok=True)

        # Upstream carries a few near-duplicate CSVs for one tool ("findstr.csv"
        # and "findstr .csv"). One tool is one hypothesis, so they are merged on
        # the tool slug and their keyword sets unioned.
        byslug: dict[str, dict] = {}
        for name in sorted(os.listdir(bdir)):
            if not name.endswith(".csv"):
                continue
            if args.limit and len(byslug) >= args.limit:
                break
            t = read_tool(os.path.join(bdir, name))
            if t is None:
                skipped += 1
                continue
            key = slug(t["tool"])
            first = byslug.get(key)
            if first is None:
                t["csv"] = name
                byslug[key] = t
                continue
            merged += 1
            seen = {a.lower() for a in first["alts"]}
            for a in t["alts"]:
                if a.lower() not in seen:
                    seen.add(a.lower())
                    first["alts"].append(a)
            first["alts"].sort(key=lambda s: (s.lower(), s))
            first["dupes"] += t["dupes"]

        for key, t in sorted(byslug.items()):
            tools += 1
            groups = chunk_alternatives(t["alts"], ALT_BUDGET)
            if len(groups) > 1:
                split_tools += 1
            for i, alts in enumerate(groups, 1):
                text = render(t, bucket, t["csv"], i, len(groups), alts)
                base = key + ("" if i == 1 else "-part%d" % i)
                path = os.path.join(odir, base + ".yaml")
                for line in text.splitlines():
                    if line.lstrip().startswith("| ") and len(line) > QUERY_LIMIT:
                        raise SystemExit("query over limit in %s" % path)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)
                written += 1

    print("tools read     : %d" % tools)
    print("csv merged     : %d (duplicate upstream file for one tool)" % merged)
    print("csv skipped    : %d (no usable keyword)" % skipped)
    print("tools split    : %d (keyword set over %d chars)" % (split_tools, ALT_BUDGET))
    print("templates written: %d" % written)
    if args.no_verify or args.limit:
        return 0
    print("--- cross-check against the CSV keyword column")
    return verify(src)


if __name__ == "__main__":
    raise SystemExit(main())
