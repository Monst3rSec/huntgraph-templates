# intent.md

Why this repository is shaped the way it is. `project.md` says what it is; `CLAUDE.md`
says how to work in it. This file says what it is *for*, so that a future change can be
judged against the intent rather than against the current code.

## The consumer decides everything

huntgraph is a threat-hunting **agent**, not a SIEM dashboard. The agent runs a query,
reads what comes back, and reasons to a verdict it has to explain. That single fact
generates every constraint in this repo:

- The agent cannot see the console, so anything it needs must be in the query result.
- The agent cannot ask a follow-up of a result set that has already been aggregated away.
- The agent has to justify its verdict, so the file must carry the reasoning, not just
  the match.

A detection rule optimises for **precision at fire time**. This corpus optimises for
**sufficiency at reasoning time**. Those pull in opposite directions, and almost every
mistake in this repo is a rule-writer's instinct applied to an agent's input.

## The three intents

### 1. A hit is not a verdict

Evidence is split into `required`, `supporting` and `contradicting` so that confidence is
composed rather than asserted:

```
encoded command                                      -> interesting
encoded command + unusual parent                     -> suspicious
encoded command + unusual parent + network activity  -> high risk
```

The `contradicting` bucket is the expensive half and the reason the corpus is worth
anything. It is what stops the agent rediscovering the same benign backup job in every
environment it is pointed at. If a new file's contradicting section is thin, the file is
not finished.

### 2. One file, one hypothesis

T1218.011 gets one file for a DLL loaded from a user-writable path and another for script
executed through a protocol handler. A single file covering "everything rundll32 does"
can match, but it cannot produce an explainable answer, and an unexplainable answer from
a hunting agent is worth less than no answer.

### 3. Honest gaps beat fake coverage

~97 Priority 1 targets rest on Module Load, Process Access and OS API Execution — the
whole T1055 family included — which this deployment does not collect. They are reported
as blocked, not skipped quietly and not approximated with command-line heuristics.
Coverage numbers that include detections that cannot detect are worse than a smaller
honest number, because someone will plan around them.

The same honesty appears inside files: browser extensions and virtual instances are
catchable at installation and opaque afterwards, and that is stated rather than papered
over.

## Where the current implementation betrays the intent

### The aggregation defect

This is the live one, and it is a direct contradiction of intent #1.

Every query terminates in `groupBy()` keyed on `ComputerName`, `UserName`,
`ParentBaseFileName`, `FileName`, with detail preserved only through
`collect([...], limit=3..5)`. Measured across the corpus:

| | |
|---|---:|
| Templates | 289 |
| `groupBy` stanzas | 1029 |
| Stanzas capped at 3-5 samples | 670 |
| Queries with a raw drill-down path | 0 |
| Templates declaring a CQL field that never reaches output | **289 (100%)** |
| Templates that declare `aid` and emit it | **0 of 289** |

So the file tells the agent "this hunt collects `aid`, `TargetProcessId`,
`TargetFileName`", the risk logic reasons over them, and the query returns a host name, a
user name and three truncated command lines. The agent is reasoning over evidence it was
never given. That is not a query-tuning nit; it is the evidence contract being violated
by every file in the repository.

The symptom reported from the field — *"it minimises the data and I cannot find the
threat"* — is exactly this, correctly observed.

### The fix, and the fix that would make it worse

The tempting correction is "drop `groupBy()`, use `sort()`, return everything". Do not.

- Aggregation is load-bearing. Process-creation volume on a real estate is millions of
  events per hour. An unaggregated hunt returns a result the agent cannot read either,
  and the counts that `risk_logic` compares against the baseline disappear.
- `sort()` is not the open alternative it looks like. It carries its own result limit and
  truncates; swapping `groupBy()` for it trades a summarised view for an arbitrary
  truncated one, while also discarding the aggregates. Strictly worse on both axes.

The defect is not that the data is grouped. It is that **the grouped row is not a
complete evidence record, and there is no way down to the raw events.** Four corrections,
in priority order:

1. **Close the declared-versus-emitted gap.** Every field in `requires.logs` appears in
   the `collect([...])` list. Mechanical, verifiable, and it alone fixes the contract
   violation in all 289 files.
2. **Add a drill-down case per hypothesis** — same filters, no aggregation — so the agent
   can pivot from a row to the untruncated events behind it. This is what actually
   restores "figure out the threat".
3. **Raise sample limits** from 3-5 to something that is a sample.
4. **Narrow group keys.** Keying on four fields fragments one behaviour across many rows
   and destroys the count the risk logic reads.

### Make the validator own it

The repo's central claim is that the validator is the contract and the mutation tests are
what make it trustworthy. Then this belongs in the validator, not in a style guide:

> **L3 (proposed):** every field declared in a `crowdstrike-ngsiem` `requires.logs`
> stanza must appear in the query output of at least one case in that file.
>
> **L4 (proposed):** every hypothesis must expose at least one case that returns raw
> events, so an aggregated finding is always resolvable to evidence.

Add the checks first and let them fail 289 times. Fixing the corpus under a failing test
is a migration; fixing it by hand-editing YAML is 289 chances to regress silently, which
is the failure mode this repo was built to refuse.
