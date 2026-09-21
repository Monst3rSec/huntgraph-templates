# CLAUDE.md

Operating instructions for an agent working in this repository.

## What this repo is

289 YAML files of threat-hunting detection knowledge, consumed by the **huntgraph**
threat-hunting agent. Each file is one hypothesis: what to query, what evidence the
result carries, and how to reason from that evidence to a verdict.

It is not an alert ruleset. Nothing here is meant to fire on its own. The consumer is
an agent that runs the query, reads the evidence back, and decides. Every design choice
follows from that: **the query exists to hand the agent facts, not to hand a human a
short list.**

## Commands

```bash
pip install -r tools/requirements.txt

python3 tools/validate.py --strict        # the contract. must pass before any commit
python3 tools/test_validator.py           # injected defects, each must be caught
python3 tools/coverage.py --priority 1 --remaining
python3 tools/coverage.py --priority 1 --blocked
python3 tools/coverage.py --markdown > task.md     # regenerate, never hand-edit
python3 tools/export_csv.py -o coverage.csv        # regenerate, never hand-edit
```

On a machine with an externally-managed Python (recent macOS), create a venv rather than
installing into the system interpreter. Nothing in the toolchain requires a global install.

`task.md` and `coverage.csv` are generated artefacts. Editing them by hand produces a
file that is wrong and will be silently overwritten.

## Hard invariants

1. **Never write a MITRE fact from memory.** Technique ids, tactics, detection
   strategies (`DET*`), analytics (`AN*`) and data components come from
   `tools/attack_extract.py` reading the STIX bundle. The validator has already caught
   one fabricated data component that was plausible and wrong.
2. **The directory carries the technique, the filename carries the behaviour.**
3. **Ids are stable.** `hg-<platform>-<behaviour>-<mitre-id>` survives rewrites of the
   description and the query. Only a change of hypothesis justifies a new id.
4. **One file, one hypothesis.** If a file needs "or" in its statement, it is two files.
5. **Do not approximate blocked telemetry.** ~97 Priority 1 targets need Module Load,
   Process Access or OS API Execution, which this deployment does not collect. A
   command-line approximation of DLL injection detects nothing while looking like
   coverage. Record it in `skipped.yaml` or leave it uncovered.
6. **Return the events, not a summary of them.** See the query output policy below. A
   query that aggregates by default hands the agent a row it cannot reason past.

## Connectors

| Connector | `language` | Files |
|---|---|---:|
| `crowdstrike-ngsiem` | `cql` | 289 |
| Wazuh | `wazuh-rules` | 127 |

Wazuh rule ids are allocated from `ruleset/wazuh-id-allocations.yaml`; field names come
from `ruleset/field-map.yaml`. A CQL case with no Wazuh rule must be named in
`not_portable`, and a case cannot be both covered and not-portable. The validator
enforces all of this at L4.

## Validator layers

| Layer | Catches |
|---|---|
| L1 structure | schema conformance; unknown keys are errors |
| L2 mitre | ids exist, and the relationships asserted are the ones MITRE publishes |
| L3 evidence | referential integrity between evidence, risk logic and verdict |
| L4 query | CQL only in `cql` cases; declared event types actually used; every declared field reaches a result row; Wazuh block well-formed |
| L5 convention | directory encodes the technique; ids unique and correctly suffixed |

## Upstream rule ingestion

Two public rule sets are triaged against this corpus:

| Source | Upstream | Tracker |
|---|---|---|
| Splunk | [research.splunk.com/detections](https://research.splunk.com/detections/) (`splunk/security_content`) | `splunk_tracker.md` |
| Elastic | [detection-rules-explorer](https://elastic.github.io/detection-rules-explorer/) (`elastic/detection-rules`) | `elk_tracker.md` |
| Sigma | [`rules-threat-hunting/windows`](https://github.com/SigmaHQ/sigma/tree/master/rules-threat-hunting/windows) (`SigmaHQ/sigma`) | `sigma_tracker.md` |

```bash
python3 tools/track_sources.py     # refetch upstream, rewrite both trackers
```

Both trackers are **generated artefacts** — regenerate, never hand-edit, same rule as
`task.md` and `coverage.csv`. Every upstream rule appears in one of them with a routing
decision, so a rule that was considered and rejected stays rejected instead of being
re-litigated the next time someone finds these repos.

A rule is queued as `convert` only when **both** halves hold:

- **The technique** is a leaf this repo does not cover, is observable on Windows, Linux or
  macOS, is not missing the telemetry its hypothesis would need, and carries at least one
  ATT&CK detection strategy — without one, L2 can never pass.
- **The upstream rule reads endpoint telemetry.** Judge this from the rule's own metadata
  (Splunk `data_source`, Elastic `index`), never from its title. A technique can be
  endpoint-observable while a particular rule for it reads CloudTrail; those are marked
  `non-endpoint-surface`, because this connector does not ingest them.

Everything else is recorded with its reason: `covered`, `blocked-telemetry`,
`out-of-scope`, `parent`, `skipped`, `unresolved-id`, `no-detection-strategy`,
`non-endpoint-surface`.

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

### Upstream rules by category

Sigma rules are also **stored**, not just tracked: `python3 tools/import_sigma.py` copies
them byte-for-byte from a pinned commit into `upstream/<category>/sigma/` and writes
`sigma_tracker.md` (Category | TTP | Rule | Description | Path). Categories are Elastic's
prebuilt-rule domains — cloud, containers, email, endpoint, identity, kubernetes, llm,
network, saas, unspecified, web — and a rule is filed by the telemetry it reads, not the
technique it maps to. All 128 current rules read Windows host logs, so all are `endpoint`.

`upstream/` is reference material: `validate.py` does not scan it, and its files are under
the Detection Rule License 1.1, not Apache-2.0 — keep them unmodified so the authors'
attribution survives. Never edit them in place; rerun the import.

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
`id` to end in a MITRE technique number, and L5 rejects any file outside `techniques/`, so
an unclassified detection is currently unrepresentable. Making it representable means
changing the id pattern, L5, the mitre block in schema and L2, and the mutation tests —
do that as its own piece of work, not as a side effect of an import.

## Query output policy

**Default: a case returns raw events.** Filter the event stream down to the behaviour and
stop. The agent gets every field on every matching event and can count, group, sort and
pivot for itself. A pre-baked `groupBy` row is a summary someone else chose, and the agent
cannot get back what it discarded.

Where the corpus stands, measured:

| | |
|---|---:|
| CQL cases | 1041 |
| Return raw events | **793** |
| Still end in `groupBy` | 248 |
| `sort()` calls | **0** |
| Files: all-raw / mixed / all-aggregated | 138 / 138 / 13 |

How it got here. All 1028 cases once ended in `groupBy()` keyed on `ComputerName`,
`UserName`, `ParentBaseFileName`, `FileName`, keeping detail only in
`collect([...], limit=3..5)`; every template declared `aid` and none returned it. 774 purely
summarising cases were made raw. Later, every remaining query ending `groupBy ... sort`
(128) lost its last two lines at the owner's direction: the `sort` went everywhere, and with
it the filter written just before it — in most cases a count threshold or join condition —
while the `groupBy` stayed. Seven of those were left with an unclosed `groupBy` and were
made raw.

**What the 248 aggregating cases do now:**

- **153 are joins.** A `case { ... }` block tags two event streams and `groupBy` on a shared
  key puts them on one row. Removing that `groupBy` alone would leave a trailing
  `| a=/.+/ and b=/.+/` asking for two fields that never share an event, returning nothing.
- **65 still end in a count threshold** (74 threshold lines), e.g. `| hosts >= 20`: the
  count exists only because of the `groupBy`.
- **82 end at the `groupBy` itself.** Most lost their threshold or join condition in the
  two-line removal, so they now return **every grouped row rather than only the rows that
  meet the hypothesis**. The agent has to apply that condition itself.

**An aggregating case must still carry every declared field to the row** — as a `groupBy`
key, a `collect([...])` entry or an aggregate alias. L4 enforces this. A case only gets credit
for a field its own event types carry: naming a file-creation field in a `collect()` over
process events returns nothing and does not count. `collect()` samples are 50, not 3-5.

### Still open

- A declared log source that no case queries is an L4 warning, and `--strict` fails on
  warnings. 19 templates had one, each backing a `supporting` evidence item nothing collected
  (an earlier pass had hidden them by pasting the field names into a `collect()` over process
  events). 13 now have a raw case that collects that evidence; SAM and NTDS read their output
  path from the export command line instead; four evidence items were removed — a `.chm`,
  `.msi`, document or stream host arriving "recently" is visible only to a generic file-write
  event, which the CrowdStrike connector does not have here, and evidence must be collectable
  from every connector a file declares.
- **13 templates have no raw case at all**, only joins and thresholds.
- **Raw-by-default is not enforced.** Nothing stops a new case from ending in `groupBy`.
  Adding that check means writing it first, letting it fail, and migrating under it.
