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

## Open defect: aggregation collapses the evidence

**Status: known, unfixed, affects all 289 files.**

Every query ends in `groupBy()` keyed on some subset of `ComputerName`, `UserName`,
`ParentBaseFileName`, `FileName`, with detail carried only by `collect([...], limit=N)`
where N is 3 to 5 in 670 of 1029 stanzas.

Measured consequence: **289 of 289 templates declare at least one CQL field in
`requires.logs` that never appears in query output.** `aid` is declared by all 289 and
emitted by none — the agent id, the one field you pivot on in NG-SIEM, is documented as
required and thrown away by every query. Also commonly lost: `ImageFileName` (63),
`ContextProcessId` (46), `TargetProcessId` (39), `TargetFileName` (28).

The agent is therefore asked to reason about evidence the query does not return.

**When you touch a query, fix it in that file.** The correction is not "remove the
aggregation":

- Aggregation is what makes 40 million process events a tractable triage surface.
  Deleting it does not help the agent, it drowns it.
- Replacing `groupBy()` with `sort()` is worse, not better. `sort()` in this dialect
  takes its own limit and truncates the result set; you would trade a summarised 500
  rows for an arbitrary first 200, and lose the counts the risk logic reads.

Do this instead:

1. **Every field in `requires.logs` reaches the output.** Add the missing ones to the
   `collect([...])` list. Cheap, mechanical, and it closes the declared-versus-emitted
   gap on its own.
2. **Raise the sample limits.** 3 command lines is not a sample of a hunt, it is a
   rounding error. 50 costs nothing at these row counts.
3. **Give every case a drill-down twin** — identical filters, no `groupBy`, so the agent
   can pivot from an interesting row to the full untruncated events behind it. This is
   the part that actually answers "I cannot figure out the threat from this".
4. **Keep the group key narrow.** Keying on four fields at once fragments one behaviour
   across many rows and hides the count that the risk logic depends on.

Do not do a repo-wide mechanical rewrite without the validator gaining a check for it
first. Add the check, let it fail 289 times, then fix under a green test.
