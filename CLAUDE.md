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
| L4 query | CQL only in `cql` cases; declared event types actually used; Wazuh block well-formed |
| L5 convention | directory encodes the technique; ids unique and correctly suffixed |

## Upstream rule ingestion

Two public rule sets are triaged against this corpus:

| Source | Upstream | Tracker |
|---|---|---|
| Splunk | [research.splunk.com/detections](https://research.splunk.com/detections/) (`splunk/security_content`) | `splunk_tracker.md` |
| Elastic | [detection-rules-explorer](https://elastic.github.io/detection-rules-explorer/) (`elastic/detection-rules`) | `elk_tracker.md` |

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
  `cloud-surface`, because this connector does not ingest them.

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

The corpus originally ended all 1028 CQL cases in `groupBy()` keyed on `ComputerName`,
`UserName`, `ParentBaseFileName`, `FileName`, keeping detail only in
`collect([...], limit=3..5)`. 774 of those are now raw. Every one of the 289 templates
declared `aid` in `requires.logs` and no query returned it; in a raw case that is moot,
because the event carries all of its fields.

**Aggregate only when the aggregation is the hypothesis.** Two cases qualify, and 254
cases in the corpus are held back by them:

- **A join.** A `case { ... }` block tags two event streams, and `groupBy` on a shared key
  (usually `ContextProcessId`) is what puts them on one row so a trailing line can require
  both: `| enumerated=/.+/ and controlled=/.+/`. Delete the `groupBy` and those two fields
  never coexist on a single event — the query returns nothing at all. 159 cases.
- **A threshold.** The hypothesis is "at breadth" or "at machine rate", and a trailing line
  states it: `| hosts >= 20`, `| connections >= 6`, `| distinct_categories >= 3`. The count
  only exists because of the `groupBy`. 179 such lines.

When you must aggregate, **every field declared in `requires.logs` still has to reach the
row** — as a `groupBy` key, inside `collect([...])`, or as an aggregate alias. That is the
rule the original corpus broke in all 289 files, and it still holds wherever aggregation
survives.

`sort()` goes with the `groupBy` it serves: 721 of the corpus's 722 `sort()` calls sorted on
an aggregate alias, so they have nothing to sort once the aggregate is gone.

### Still open

14 templates consist entirely of join/threshold cases and so return no raw events anywhere.
All 14 still declare fields — `aid` among them — that no query returns. Closing that means
either giving each a raw companion case (which needs a matching `not_portable` entry, since
L4 requires every CQL case to carry a Wazuh rule or declare itself non-portable), or
widening their `collect([...])` lists to carry the declared fields.

Neither the raw-by-default rule nor the declared-fields rule is enforced by the validator
yet. Adding them means writing the check first, letting it fail, and migrating under it —
never a hand pass over 289 files.
