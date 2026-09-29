# AGENTS.md

Operating rules for an agent working in this repository. `CLAUDE.md` imports this file, so
it is the only copy. Why the repository exists is in [intent.md](intent.md); the order of
work, phase by phase, is in [adlc.md](adlc.md).

## What this repo is

YAML threat-hunting detection knowledge, consumed by the **huntgraph** threat-hunting agent.
Each file is one hypothesis: what to query, what evidence the result carries, and how to
reason from that evidence to a verdict. It is not an alert ruleset: **the query exists to
hand the agent facts, not to hand a human a short list.**

## Commands

```bash
pip install -r tools/requirements.txt

python3 tools/validate.py --strict        # the contract. must pass before any commit
python3 tools/test_validator.py           # injected defects, each must be caught
python3 tools/coverage.py --priority 1 --remaining
python3 tools/coverage.py --priority 1 --blocked
python3 tools/coverage.py --markdown > task.md     # regenerate, never hand-edit
python3 tools/export_csv.py -o coverage.csv        # regenerate, never hand-edit
python3 tools/stats.py                             # stats.md, regenerate, never hand-edit
python3 tools/track_sources.py [--source sigma]    # tracker/*_tracker.md, regenerate, never hand-edit
python3 tools/attack_extract.py T1218.011 --json   # the only source of MITRE facts
python3 tools/alloc_rule_ids.py --alloc <file>     # reserve a Wazuh rule-id block
python3 tools/add_wazuh_block.py <file>            # scaffold a Wazuh block from the CQL cases
python3 tools/gen_keyword_templates.py --source <thk-checkout>   # hunt/keyword/, regenerate, never hand-edit
```

On a machine with an externally-managed Python (recent macOS), create a venv rather than
installing into the system interpreter. Nothing in the toolchain requires a global install.

`task.md`, `coverage.csv`, `stats.md`, `tracker/*_tracker.md`, `hunt/keyword/**.yaml` and
`unclassified-threat-check/` are generated artefacts. Editing them by hand produces a file
that is wrong and will be silently overwritten.

## Hard invariants

1. **Never write a MITRE fact from memory.** Technique ids, tactics, detection
   strategies (`DET*`), analytics (`AN*`) and data components come from
   `tools/attack_extract.py` reading the STIX bundle. The validator has already caught
   one fabricated data component that was plausible and wrong.
2. **The first directory carries the category, the next the technique, the filename the behaviour.**
   See Categories below.
3. **Ids are stable.** `hg-<platform>-<behaviour>-<mitre-id>` survives rewrites of the
   description and the query. Only a change of hypothesis justifies a new id.
4. **One file, one hypothesis.** If a file needs "or" in its statement, it is two files.
5. **Do not approximate blocked telemetry.** ~97 Priority 1 targets need Module Load,
   Process Access or OS API Execution, which this deployment does not collect. A
   command-line approximation of DLL injection detects nothing while looking like
   coverage. Record it in `skipped.yaml` or leave it uncovered.
6. **Return the events, not a summary of them.** See the query output policy below. A
   query that aggregates by default hands the agent a row it cannot reason past.

## Categories

Templates live at `hunt/<category>/<Txxxx-slug>[/<Txxxx.yyy-slug>]/<behaviour>.yaml`, and
the only things under `hunt/` that are not one are `hunt/README.md` and the generated
`hunt/keyword/` tree (see Keyword sweeps below). A category folder exists only once
it holds a template. The category is one of Elastic's prebuilt-rule domains — cloud, containers, email,
endpoint, identity, kubernetes, llm, network, saas, unspecified, web — and L5 rejects
anything else. It records **what the hunt is about**, not what the query reads: every
template reads the CrowdStrike endpoint sensor, so filing by telemetry would put all of them
in one folder.

A whole technique family shares one category, so its sub-technique folders move with it:

| Category | Technique families |
|---|---|
| network | C2 and exfiltration (T1001, T1008, T1071, T1090, T1095, T1102, T1104, T1105, T1132, T1205, T1219, T1568, T1571, T1572, T1659; T1011, T1030, T1041, T1048, T1567), traffic interception and probing (T1040, T1046, T1187, T1557), host-to-host movement (T1021, T1133, T1210, T1563, T1570) |
| identity | accounts and authentication (T1078, T1098, T1110, T1136, T1550, T1556, T1558, T1606, T1621, T1649), directory (T1207, T1484), and T1003.006 DCSync |
| email | T1114, T1534, and phishing delivery T1566 (attachment, link) |
| web | T1505 |
| containers | T1611 |
| endpoint | everything else, including discovery run on the host |

T1003.006 is the one split: DCSync is domain-controller replication, so it sits under
`identity/T1003-os-credential-dumping/` while the rest of T1003 stays in `endpoint`. A new
technique goes where its behaviour belongs; when in doubt, it is `endpoint`. Moving a
template between categories changes only its path — ids, Wazuh rule ids and tracker links
are keyed by id.

## Connectors

| Connector | `language` | Carried by |
|---|---|---|
| `crowdstrike-ngsiem` | `cql` | every template |
| Wazuh | `wazuh-rules` | templates whose cases port; counts are in [stats.md](stats.md) |

Wazuh rule ids are allocated from `ruleset/wazuh-id-allocations.yaml`; field names come
from `ruleset/field-map.yaml`. A CQL case with no Wazuh rule must be named in
`not_portable`, and a case cannot be both covered and not-portable. The validator
enforces all of this at L4.

## Validator layers

L1 short-circuits a file; the rest all run, so one pass reports everything wrong with it.

| Layer | Catches |
|---|---|
| L1 structure | parses; conforms to `schema/detection.schema.json`; unknown keys are errors |
| L2 mitre | every ATT&CK id exists, and the relationships asserted are the ones MITRE publishes: technique↔tactic, sub↔parent, DET↔technique, AN↔DET, platform↔technique, data component↔analytic |
| L3 evidence | evidence ids unique; `risk_logic` and `verdict` reference only real ids; escalation tiers include the required evidence and never cite contradicting evidence; every evidence field is declared in `requires.logs` for every connector |
| L4 query | CQL only in `cql` cases; declared event types actually used; every declared field reaches a result row and every declared source is read; Wazuh blocks well-formed and inside their allocated id block |
| L5 convention | directory encodes the category and technique; ids unique and end with the most specific MITRE id |

`tools/test_validator.py` injects known defects into a good file and asserts the right layer
catches each one; run it whenever the schema or the validator changes.

## Keyword sweeps

`hunt/keyword/` holds one template per offensive or greyware tool in
[mthcht/ThreatHunting-Keywords](https://github.com/mthcht/ThreatHunting-Keywords), filed by
that project's own A–Z buckets and generated by `tools/gen_keyword_templates.py`. Each one
ORs every keyword upstream publishes for that tool into a single case-insensitive filter on
`CommandLine`, with no `#event_simpleName` scope, splitting into `-partN` templates at the
30,000-character NG-SIEM query limit. Each run ends with a cross-check that re-reads the
CSVs and fails if a distinct keyword did not reach a query.

It sits **outside the validated corpus on purpose**: the hunt is anchored on a tool name,
not a technique, so it cannot satisfy L5's layout. `validate.py`, `coverage.py` and
`add_wazuh_block.py` prune the directory, and `stats.py` and `track_sources.py` glob
`hunt/*/T*/**` and never reach it. Nothing there is checked by L1–L5 and nothing counts
toward coverage.

The `mitre:` block in those files is the **upstream CSV's mapping carried verbatim**, not a
fact this repo asserts — some of it cites revoked ids. Invariant 1 still governs everything
under a category folder; `hunt/keyword/README.md` explains the split.

## Upstream rule ingestion

Three public rule sets are triaged against this corpus. None of them is stored here:

| Source | Upstream | Tracker |
|---|---|---|
| Splunk | [research.splunk.com/detections](https://research.splunk.com/detections/) (`splunk/security_content`) | `tracker/splunk_tracker.md` |
| Elastic | [detection-rules-explorer](https://elastic.github.io/detection-rules-explorer/) (`elastic/detection-rules`) | `tracker/elk_tracker.md` |
| Sigma | [`rules-threat-hunting/windows`](https://github.com/SigmaHQ/sigma/tree/master/rules-threat-hunting/windows) (`SigmaHQ/sigma`), pinned to one commit | `tracker/sigma_tracker.md` |

```bash
python3 tools/track_sources.py                    # refetch upstream, rewrite all three trackers
python3 tools/track_sources.py --source sigma     # one source only
```

All three trackers are **generated artefacts** — regenerate, never hand-edit, same rule as
`task.md` and `coverage.csv`. Every upstream rule appears in one of them with a routing
decision, so a rule that was considered and rejected stays rejected instead of being
re-litigated the next time someone finds these repos.

A rule is queued as `convert` only when **both** halves hold:

- **The technique** is a leaf this repo does not cover, is observable on Windows, Linux or
  macOS, is not missing the telemetry its hypothesis would need, and carries at least one
  ATT&CK detection strategy — without one, L2 can never pass.
- **The upstream rule reads endpoint telemetry.** Judge this from the rule's own metadata
  (Splunk `data_source`, Elastic `index`, Sigma `logsource`), never from its title. A technique can be
  endpoint-observable while a particular rule for it reads CloudTrail; those are marked
  `non-endpoint-surface`, because this connector does not ingest them.

Everything else is recorded with its reason: `covered`, `blocked-telemetry`,
`out-of-scope`, `parent`, `skipped`, `unresolved-id`, `no-detection-strategy`,
`non-endpoint-surface`, and for Sigma `blocked-logsource`. A Sigma rule states exactly what it
reads, so it is blocked per rule, whatever its technique routes to, when its logsource is a
module load, process access, remote thread, named pipe, file open/delete/rename/timestamp
change, PowerShell script block or module event, or a Windows event channel — none of which
the CrowdStrike sensor supplies here.

**`convert` is a technique-level judgement, not a behaviour-level one.** The tracker asks
whether a rule's *technique* has a template. It cannot tell you whether the *behaviour* is
already covered under a different technique, and upstream labelling differs from this
corpus's. The worked example: a dozen Splunk rules labelled T1566.001 ("Windows Office
Product Spawned Uncommon Process", "… Spawned MSDT", "Suspicious MS Office Child Process")
describe exactly what `document-spawning-execution-chain.yaml` already covers as
`document-parent-interpreter-child` under T1204.002. T1566.001 is uncovered, so they all
queue as `convert`; authoring them would duplicate an existing hypothesis under a second id.

So before writing anything, read the queued rule's behaviour against the existing corpus,
not just its technique id. If a template already expresses it, the rule is a duplicate:
leave the template alone and move on. A found duplicate is a correct outcome of triage, not
a gap.

Also treat `surface` as a floor, not a guarantee. It reads the upstream rule's own
`data_source`/`index`; a rule that declares neither is classed `unknown` and refused,
because absence of a declared source is not evidence of endpoint visibility — GitHub audit,
mail-gateway and ML rules all land there.

### Every rule lands as a hunt template

Rules may come from anywhere — Elastic, Splunk, Sigma, a vendor blog, a report, an analyst's
own idea — but they enter this repository in **one form only**: a YAML template in the
`hunt/<category>/<Txxxx-slug>/[<Txxxx.yyy-slug>/]<behaviour>.yaml` structure, validated like
every other. Never add a rule in its upstream format (EQL, KQL, ES|QL, SPL, TOML, Sigma YAML),
never create a new per-source folder beside the templates, and never keep a "raw" copy to
convert later. Upstream rules are read at their source and triaged by `track_sources.py`;
there is no exception.

Working a rule is create, update or reject — the CRUD of this corpus:

- **Create** a new template when the behaviour has no template yet.
- **Update** the existing template when it already holds the hypothesis and the rule adds
  something it lacked — a case, a child process, a path. Bump `version` (minor), add the
  case's Wazuh rule or its `not_portable` entry, wire any new evidence into `risk_logic` and
  `verdict`, and add the rule's URL to `info.references`.
- **Reject** the rule when its distinguishing evidence needs telemetry this deployment does
  not collect (module load, process access, OS API) or when a template already covers it
  completely. Do not reference a rule from a template that does not actually cover it just
  to clear the tracker; an outstanding row is honest, a false "done" is not.
- **Delete** a template only when its hypothesis is wrong or fully duplicated, never because
  an upstream rule was removed. Its Wazuh ids stay allocated.

### Converting is authoring, not porting

An upstream rule is not a hunting hypothesis — that distinction is the reason this corpus
exists. A conversion rewrites the behaviour as a hypothesis with its own evidence buckets,
risk logic and verdict, and the query becomes hand-written CQL against CrowdStrike event
names. Splunk SPL, Elastic EQL/KQL/ES|QL are all rejected outright by L4, so nothing is
translated mechanically. Expect several rules to collapse into one hypothesis, and expect
some to be dropped after reading them.

**Put the upstream raw URL in `info.references`.** That is how `track_sources.py` marks a
rule converted; omit it and the tracker will keep reporting the rule as outstanding.

### Unmapped rules

Rules with no ATT&CK mapping go to `unclassified-threat-check/<source>-unmapped.md` as a
staged list. They are **not** templates and are not validated: the schema requires every
`id` to end in a MITRE technique number, and L5 rejects any template outside a technique
folder under `hunt/`, so
an unclassified detection is currently unrepresentable. Making it representable means
changing the id pattern, L5, the mitre block in schema and L2, and the mutation tests —
do that as its own piece of work, not as a side effect of an import.

## Query output policy

**Default: a case returns raw events.** Filter the event stream down to the behaviour and
stop. The agent gets every field on every matching event and can count, group, sort and
pivot for itself. A pre-baked `groupBy` row is a summary someone else chose, and the agent
cannot get back what it discarded.

Current counts — raw versus aggregating, and what each aggregating case does — are in
[stats.md](stats.md) under "Query shape". Its buckets do not overlap: a join is counted as a
join even when it also ends in a threshold.

**Aggregate only when the aggregation is the hypothesis.** Two shapes qualify:

- **A join.** A `case { ... }` block tags two event streams and `groupBy` on a shared key
  puts them on one row, so a trailing `| a=/.+/ and b=/.+/` can require both. Removing the
  `groupBy` alone leaves that line asking for two fields that never share an event — the
  query returns nothing.
- **A threshold.** The hypothesis is "at breadth" or "at machine rate", written as
  `| hosts >= 20` or `| connections >= 6`; the count exists only because of the `groupBy`.

Some aggregating cases end at the `groupBy` with no condition after it. Most lost their
threshold or join condition when the last two lines of every `groupBy ... sort` query were
removed at the owner's direction, so they return **every grouped row rather than only the
rows that meet the hypothesis**, and the agent has to apply the condition. No `sort()`
remains anywhere.

**An aggregating case must still carry every declared field to the row** — as a `groupBy`
key, a `collect([...])` entry or an aggregate alias. L4 enforces this, and credits a field
only to a case whose own event types carry it: naming a file-creation field in a `collect()`
over process events returns nothing and does not count. `collect()` samples are 50.

**Every declared log source must be read by some case.** L4 reports an unread source as a
warning and `--strict` fails on warnings. When one appears, the fix is at the evidence: add a
case that collects it, source the evidence from telemetry that can see it, or remove the
evidence item if nothing this connector collects ever could — never paste the field into an
unrelated `collect()` to satisfy the check.

### Still open

- **Some templates have no raw case at all**, only joins and thresholds.
- **Many evidence items cite the `baseline`, `derived` or `identity_context`
  pseudo-sources.** Their reasoning assumed counts the query used to pre-compute; many of
  those counts and the thresholds on them are gone, and nothing in the files yet tells the
  agent that deriving them is now its job.
- **Raw-by-default is not enforced.** Nothing stops a new case from ending in `groupBy`.
  Adding that check means writing it first, letting it fail, and migrating under it.
