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
python3 tools/test_validator.py           # 25 injected defects, each must be caught
python3 tools/coverage.py --priority 1 --remaining
python3 tools/coverage.py --priority 1 --blocked
python3 tools/coverage.py --markdown > task.md     # regenerate, never hand-edit
python3 tools/export_csv.py -o coverage.csv        # regenerate, never hand-edit
```

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
6. **Every field declared in `requires.logs` must actually reach the query output.**
   See the open defect below; this is currently violated by every file in the repo.

## Connectors

Two are emitted. `project.md` used to claim CQL only; that is no longer true.

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

## The evidence-completeness rule (enforced)

**L4 `check_query_emits_declared`: every field a `crowdstrike-ngsiem` `requires.logs`
stanza declares must reach the output of at least one CQL case.**

A field survives aggregation only as a `groupBy` key, inside a `collect([...])`, as an
aggregate alias, or as an assignment made before the aggregation. Filtering on a field
and then aggregating it away is invisible in the query text, which is why this is a
validator error and not a review convention. Mutation case: *"declared field that no
query returns"*.

The corpus shipped 289 files violating it — every one declaring `aid` and none returning
it. That is now fixed: 100% of declared CQL telemetry reaches the result row, and
`collect()` samples are 50 rather than 3.

When you add or edit a query:

- **Anything you declare, you return.** The validator will catch you, but the point is to
  ask what the agent needs, not to satisfy the check.
- **Keep the group key narrow.** Keying on four fields fragments one behaviour across
  many rows and hides the count `risk_logic` reads. Detail belongs in `collect()`, not in
  the key.
- **Do not "fix" width by removing the aggregation.** Aggregation is load-bearing at
  process-event volume. And `sort()` is not the open alternative it appears to be: it
  carries its own result limit and discards the aggregates the risk logic compares
  against the baseline. Strictly worse on both axes.

### Still open: no raw drill-down

No hypothesis exposes a case that returns unaggregated events, so an interesting row
cannot be resolved to the events behind it. Closing this means a drill-down case per
hypothesis and a matching `not_portable` entry for each (L4 requires every CQL case to
have a Wazuh rule or be declared non-portable). It belongs behind its own validator check,
added first and allowed to fail, same as this one.
