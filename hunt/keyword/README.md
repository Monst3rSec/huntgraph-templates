# hunt/keyword

Tool-keyword sweeps generated from
[mthcht/ThreatHunting-Keywords](https://github.com/mthcht/ThreatHunting-Keywords), one
template per tool, foldered by the same A–Z buckets upstream uses.

```
hunt/keyword/<bucket>/<tool-slug>[-partN].yaml
```

```bash
git clone --depth 1 https://github.com/mthcht/ThreatHunting-Keywords /tmp/thk
python3 tools/gen_keyword_templates.py --source /tmp/thk
```

Every `.yaml` here is **generated — regenerate, never hand-edit**, the same rule as
`task.md` and `coverage.csv`. Fixes belong in `tools/gen_keyword_templates.py`. This README
is the one hand-written file in the tree; don't `rm -rf` the directory to regenerate.

## What the hunt is

The hypothesis is the tool's own vocabulary. A tool is invoked by its switches and function
names and installs itself under its published filenames, and those strings are specific
enough that nothing else on the estate emits them. Each template ORs one tool's keywords
into a single filter over raw events:

```
CommandLine=/(keyword1|keyword2|…)/i
```

There is deliberately **no `#event_simpleName` filter**. A keyword is worth seeing on
whatever event carries the field, so the sweep is scoped by field alone; `requires.logs`
still records which event types supply `CommandLine` and `TargetFileName`.

Raw events, per the [query output policy](../../AGENTS.md#query-output-policy) — no
`groupBy`, no `select`, no `sort`. The agent reads the host, the user, the parent and the
full command line and decides for itself whether the run was sanctioned.

A second case, `dropped-tool-files`, runs the subset of keywords that name a file on disk
against `TargetFileName`, which catches the tool at staging and survives the operator
renaming the launcher.

## Keyword coverage is checked, not assumed

Every run ends with a cross-check that re-reads each CSV and confirms that each distinct
value in its `keyword` column reached the query generated for its tool. The generator exits
non-zero if any did not, so a silent gap cannot ship:

```
distinct keywords: 63140
unusable keyword : 0 (empty or wildcard-only after stripping)
missing from query: 0
```

Pass `--no-verify` to skip it. It is also skipped under `--limit`, where only part of the
corpus is written.

## Why it is outside the validated corpus

These hunts are anchored on a **tool name, not a MITRE technique**, so they cannot satisfy
L5's `hunt/<category>/<Txxxx-slug>/` layout, and their ids are `hg-any-keyword-<tool>`
rather than ending in a technique id. `tools/validate.py`, `tools/coverage.py` and
`tools/add_wazuh_block.py` prune this directory; `tools/stats.py` and
`tools/track_sources.py` glob `hunt/*/T*/**` and never reach it. So:

- nothing here is checked by L1–L5, and nothing here counts toward coverage or stats;
- the `mitre:` block carries the **upstream CSV's own ATT&CK mapping verbatim**. It has not
  been checked against the STIX bundle by `tools/attack_extract.py`, and some of it is
  stale (upstream still cites revoked ids such as T1208). Treat it as a pointer, not as a
  fact this repo asserts — invariant 1 in [AGENTS.md](../../AGENTS.md#hard-invariants)
  applies to the validated corpus, and this directory is the reason the distinction is
  written down here.

A keyword sweep that proves its worth should be rewritten as a real hypothesis under a
category and technique folder, where it gets validated like everything else.

## Generation rules

| Rule | Why |
|---|---|
| Keywords come from `metadata_keyword_regex`, stripped of its `.{0,1000}` padding | Upstream's own escaping is more reliable than re-escaping the glob. A CSV whose header omits that column falls back to the raw `keyword` glob. |
| Every keyword in the `keyword` column is carried | Including the ones upstream marks proxy-only. The cross-check above is what guarantees it. |
| A keyword is carried once | Deduplicated on the raw keyword string and on the regex it compiles to, both case-insensitively, since the query itself is case-insensitive. Upstream repeats a keyword across rows, sometimes shipping two different regexes for one keyword; the count dropped is stated in each template's description. |
| A keyword whose regex contains `\|` is wrapped in `(?:…)` | Sixteen of them do (`XWorm\s(V\|v)\d+`). Left bare, the pipe would rebind the surrounding alternation and the query would match far more than the keyword. |
| A query is capped at 30,000 characters; the alternation is packed to 28,500 | The NG-SIEM limit. Eight tools exceed it and split into `-part2`, `-part3`, … templates, each a complete hunt over its slice of the keywords. rclone's 1,408 keywords need four. |
| Near-duplicate upstream CSVs for one tool are merged | Upstream ships both `findstr.csv` and `findstr .csv`. One tool is one hypothesis, so the keyword sets are unioned. |
| `severity` maps `metadata_severity_score` | ≥9 critical, ≥7 high, ≥4 medium, else low. |

## Reading the results

A match means a copy of the tool's strings appeared — not that an intrusion happened.
Red-team engagements, security products quarantining a sample, and an engineer reading the
project all reproduce the evidence, and each template's `false_positive` block says how to
tell them apart. The shorter filename keywords collide with unrelated software; a collision
repeats at volume across many hosts with a stable parent, where real tool use is sparse and
varied.
