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

## The aggregation decision

Intent #1 says a hit is not a verdict: the agent composes confidence from evidence. That
only works if the evidence arrives. For most of this corpus's life it did not.

Every one of the 1028 CQL cases ended in `groupBy()` keyed on `ComputerName`, `UserName`,
`ParentBaseFileName` and `FileName`, with detail preserved only through
`collect([...], limit=3..5)`. All 289 templates declared `aid` in `requires.logs` and no
query returned it. The file told the agent "this hunt collects `aid`, `TargetProcessId`,
`TargetFileName`", the risk logic reasoned over them, and the query returned a host name,
a user name and three truncated command lines.

The symptom reported from the field — *"it minimises the data and I cannot find the
threat"* — was exactly this, correctly observed.

### What was done

| | original | first pass | now |
|---|---:|---:|---:|
| CQL cases ending in `groupBy` | 1028 | 254 | **248** |
| Cases returning raw events | 0 | 774 | **793** |
| `sort()` calls | 722 | 128 | **0** |
| Files: all-raw / mixed / all-aggregated | 0 / 0 / 289 | 137 / 138 / 14 | 138 / 138 / 13 |
| `collect()` sample size | 3-5 | 3-5 | 50 |

A raw case filters the event stream to the behaviour and stops. Every field on every
matching event reaches the agent, which counts, groups and pivots for itself.

The second step was blunter, and deliberately so. Every query still ending `groupBy ... sort`
— 128 of them — lost its last two lines at the owner's direction, on the grounds that a
`groupBy` exposes too few columns to reason from. That removed every remaining `sort`, and
with it whatever filter preceded it: in most cases the count threshold or join condition
that *was* the hypothesis. Those queries still aggregate but now return every grouped row
instead of only the ones meeting the condition, so applying the condition is the agent's
job. Seven were left with an unclosed `groupBy` and were made raw.

### A correction to what this file used to say

This document previously argued, twice and at length, that removing the aggregation was
the wrong fix — that it would drown the agent and destroy the counts `risk_logic` reads.
That was too broad, and acting on it would have preserved the defect it was describing.

What the corpus actually shows is a split the earlier argument missed:

- **774 cases were pure summarisation.** The `groupBy` computed a count nobody's logic
  consumed, and `collect()` sampled 3-5 rows out of the evidence. An agent given the raw
  events can compute that count itself, and any other count it wants. The aggregation was
  pure loss.
- **254 cases are not summarisation.** In 159 the `groupBy` is a *join*: a `case { ... }`
  block tags two event streams and grouping on a shared key is the only thing putting them
  on one row, so `| enumerated=/.+/ and controlled=/.+/` can demand both. Strip it and
  those fields never coexist on one event — the query returns nothing, which is worse than
  a narrow row. In 179 trailing lines the count *is* the hypothesis: `| hosts >= 20`,
  `| connections >= 6`, `| distinct_categories >= 3` are how "at breadth" and "at machine
  rate" are written down. Remove the `groupBy` and the filter references a field that does
  not exist.

So the blunt instruction — drop `groupBy` and `sort` everywhere — was right for three
quarters of the corpus and would have silently broken the rest. The distinction between
summarising and correlating is the thing worth remembering, not either blanket rule.

One further correction: this file previously asserted that `sort()` "carries its own result
limit and truncates". That was written from memory of the dialect and never verified
against LogScale's documentation, and it should not have been stated as fact. What is
measurable from the corpus is narrower and sufficient: 721 of 722 `sort()` calls sorted on
an aggregate alias, so they have nothing left to sort once the aggregate is gone. That is
why 594 of them were removed alongside the `groupBy` they served.

### What is still open

- **Resolved: 19 templates declared a log source no case queried**, each backing a
  `supporting` evidence item nothing collected. An earlier pass claimed "100% of declared
  telemetry" by pasting those field names into a `collect()` over process events, where they
  can never be populated; that claim was false for these files. The validator now credits a
  field only to a case whose event types carry it. 13 files gained a raw case collecting the
  evidence; SAM and NTDS now read their output path from the export command line; four
  evidence items (a `.chm`, `.msi`, document or stream host arriving recently) were removed,
  because only a generic file-write event could see them and the CrowdStrike connector has
  none here. The CHM hunt's `suspicious` tier now rests on its required evidence alone.
- **13 templates have no raw case at all.**
- **471 evidence items cite the `baseline` pseudo-source**, plus 27 `derived` and 16
  `identity_context`. Their reasoning assumed counts the query pre-computed; many of those
  counts and the thresholds on them are gone, and nothing in the files yet tells the agent
  that deriving them is now its job.

### Make the validator own it

The repo's central claim is that the validator is the contract and the mutation tests are
what make it trustworthy. So:

> **L4 `check_query_emits_declared` (shipped):** every field declared in a
> `crowdstrike-ngsiem` `requires.logs` stanza must reach a result row. A raw case returns
> whole events, so it carries every field of the sources whose event types it reads; an
> aggregating case must name the field as a `groupBy` key, `collect()` entry or alias —
> and only gets credit if its own event types carry that field. Mutations: *"declared
> field that no query returns"* and *"declared field only named in a collect() over the
> wrong events"*.
>
> **L4 (still to write):** raw-by-default — a case should not end in `groupBy` unless the
> aggregation is a join or a threshold.

Write the check first and let it fail. Fixing the corpus under a failing test is a
migration; fixing it by hand-editing YAML is 289 chances to regress silently, which is the
failure mode this repo was built to refuse.
