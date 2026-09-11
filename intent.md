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

### The aggregation defect (fixed for width, open for depth)

This was a direct contradiction of intent #1, and it is what the field report described:
*"it minimises the data and I cannot find the threat."* Correctly observed.

Every query terminated in `groupBy()` keyed on `ComputerName`, `UserName`,
`ParentBaseFileName` and `FileName`, preserving detail only through
`collect([...], limit=3..5)`. Measured before and after:

| | before | after |
|---|---:|---:|
| Declared CQL telemetry reaching the result row | 77% | **100%** |
| Templates declaring a field no query returns | 289 of 289 | **0** |
| Templates declaring `aid` and returning it | 0 of 289 | **289** |
| Evidence fields per aggregated row (median) | 1 | 2 |
| `collect()` sample size | 3-5 | 50 |
| Hypotheses exposing a raw drill-down case | 0 | **0** |

The file told the agent "this hunt collects `aid`, `TargetProcessId`, `TargetFileName`",
the risk logic reasoned over them, and the query returned a host name, a user name and
three truncated command lines. The agent was reasoning over evidence it was never given.

### The fix, and the fix that would have made it worse

The tempting correction was "drop `groupBy()`, use `sort()`, return everything". It was
rejected, and it is worth recording why, because the instinct will recur:

- Aggregation is load-bearing. Process-creation volume on a real estate is millions of
  events per hour. An unaggregated hunt returns something the agent cannot read either,
  and the counts `risk_logic` compares against the baseline disappear.
- `sort()` is not the open alternative it looks like. It carries its own result limit and
  truncates, so swapping `groupBy()` for it trades a summarised view for an arbitrary
  truncated one while also discarding the aggregates. Worse on both axes.
- `table()`, named in the original report, does not appear anywhere in the corpus.

The defect was never that the data is grouped. It was that **the grouped row was not a
complete evidence record, and there was no way down to the raw events.** The first half is
closed. The second is not.

### Still open: depth

An analyst or agent can now see every field the hunt promised, but still only as an
aggregate. There is no case that returns unaggregated events, so an interesting row cannot
be resolved to the events behind it. That is the remaining half of "figure out the threat",
and it is a structural change: a drill-down case per hypothesis, each needing a
`not_portable` entry, because L4 requires every CQL case to carry a Wazuh rule or declare
itself non-portable.

### Make the validator own it

The repo's central claim is that the validator is the contract and the mutation tests are
what make it trustworthy. Then this belongs in the validator, not in a style guide:

> **L4 `check_query_emits_declared` (shipped):** every field declared in a
> `crowdstrike-ngsiem` `requires.logs` stanza must appear in the query output of at least
> one case in that file. Mutation: *"declared field that no query returns"*.
>
> **L4 (still to write):** every hypothesis must expose at least one case that returns raw
> events, so an aggregated finding is always resolvable to evidence.

The first was added before the corpus was touched, allowed to fail 289 times, and the
migration then ran under it. Do the same for the second. Fixing the corpus under a failing
test is a migration; fixing it by hand-editing YAML is 289 chances to regress silently,
which is the failure mode this repo was built to refuse.
