# Agent Development Life Cycle (ADLC)

How an AI agent, or a person working the same way, develops this corpus: from a source of
detection intent to a validated, committed template. The rules each phase applies are in
[AGENTS.md](AGENTS.md); why they exist is in [intent.md](intent.md). This file is the order
of work and the gate at the end of each phase.

```
1 Intake -> 2 Triage -> 3 Ground truth -> 4 Author -> 5 Validate
         -> 6 Regenerate -> 7 Review & commit -> 8 Feedback -> (back to 1)
```

A phase that fails its gate goes back, not forward. Stopping at triage with "duplicate" or
"blocked" is a finished piece of work, not an abandoned one.

## 1. Intake

**Input:** a source of detection intent — an uncovered ATT&CK target, an upstream rule
(Splunk, Elastic, Sigma), a report, an analyst's idea, or feedback from a hunt.

| Source | How to find work |
|---|---|
| ATT&CK gaps | `python3 tools/coverage.py --priority 1 --remaining` |
| Upstream rules | `python3 tools/track_sources.py [--source splunk\|elastic\|sigma]`, then the `convert` rows in `tracker/*_tracker.md` |
| Everything else | the source itself; note its URL for `info.references` |

**Gate:** the behaviour can be stated in one sentence naming one attacker action.

## 2. Triage

Decide **create, update or reject** before writing anything.

1. Map the behaviour to an ATT&CK leaf technique.
2. Search the corpus for the *behaviour*, not only the technique id. Upstream labelling
   differs from this corpus's, and a rule queued as `convert` is often a hypothesis that
   already exists under another technique.
3. Check the telemetry. If the distinguishing evidence needs module load, process access, OS
   API, a file open/delete/rename, PowerShell script-block text or a Windows event channel,
   it cannot be written here. Check `python3 tools/coverage.py --priority 1 --blocked` and
   `skipped.yaml`.

| Outcome | When | Action |
|---|---|---|
| Create | no template holds the behaviour and the telemetry exists | go to 3 |
| Update | a template holds the hypothesis and the source adds a case, path or child | go to 3, scoped to that template |
| Reject: duplicate | a template already covers it completely | stop; change nothing |
| Reject: blocked | the evidence needs telemetry that is not collected | stop; record in `skipped.yaml` if the whole target is blocked |

**Gate:** the outcome is one of the four, with a reason you could write in one line.

## 3. Ground truth

Collect every fact the template will assert, from authoritative sources only.

- `python3 tools/attack_extract.py <Txxxx.yyy> --json`: tactics, platforms, detection
  strategies, analytics, and each analytic's log sources and data components. Never from
  memory.
- CrowdStrike event names and fields: only ones already proven in the corpus or documented.
  If a field is uncertain, build on one that is certain.
- `ruleset/field-map.yaml` for logical field names and their Wazuh equivalents.

**Gate:** every MITRE id, event type and field you intend to use has a source.

## 4. Author

Write or change exactly one hypothesis at
`hunt/<category>/<Txxxx-slug>/[<Txxxx.yyy-slug>/]<behaviour>.yaml`.

- **Placement:** the category comes from the family table in AGENTS.md; the filename is the
  behaviour in kebab case; the id is `hg-<platform>-<behaviour>-<mitre-id>`.
- **Hypothesis:** one attacker behaviour, with its legitimate twin in `legitimate_behavior`.
- **Query:** CrowdStrike CQL. Each case returns raw events unless the aggregation *is* the
  hypothesis (a join or a threshold). Cases must be meaningfully different hunts.
- **Evidence:** `required`, `supporting` and `contradicting`, each item with an
  `indicates:`; wire every item into `risk_logic` and `verdict`. Real environmental exceptions
  go in `false_positive`.
- **Wazuh:** if the file has a Wazuh block, every CQL case gets a rule inside the file's
  allocated id block or a `not_portable` entry with its reason. New Wazuh blocks get ids from
  `python3 tools/alloc_rule_ids.py --alloc <file>`; `tools/add_wazuh_block.py` scaffolds the
  mechanical part.
- **Update:** bump `version` (minor), keep the `id`, and add the source URL to
  `info.references`. For an upstream rule this must be its raw URL, because that is how the
  tracker marks it converted.

**Gate:** you can read the file top to bottom and explain how each verdict tier is reached.

## 5. Validate

```bash
python3 tools/validate.py --strict <path>   # the file you touched
python3 tools/validate.py --strict          # the whole corpus
python3 tools/test_validator.py             # when the schema or validator changed
```

Fix causes, not symptoms: never paste a field into an unrelated `collect()` or cite a rule you
did not cover just to satisfy a check.

**Gate:** zero errors and zero warnings.

## 6. Regenerate

Rebuild every generated artefact the change affects, in this order, because later steps read
earlier outputs:

```bash
python3 tools/export_csv.py -o coverage.csv
python3 tools/track_sources.py --source <source>   # if an upstream rule was worked
python3 tools/coverage.py --markdown > task.md
python3 tools/stats.py
```

**Gate:** no generated file was edited by hand; the tracker shows the rule as converted, or
still outstanding if it was rejected.

## 7. Review and commit

- Review the diff as the consuming agent would: can every declared field reach a result row,
  and does each evidence item say what it indicates?
- Commit templates and their regenerated artefacts together, with a message that lists
  created, updated and rejected items and the reason for each rejection.
- CI (`.github/workflows/validate.yml`) re-runs the mutation test and `validate.py --strict`.

**Gate:** CI passes.

## 8. Feedback

The huntgraph agent runs the templates. What it learns returns as intake:

| Signal from hunting | Change |
|---|---|
| A benign pattern keeps recurring | add `contradicting` evidence or a `false_positive` |
| A true positive was missed | add a case or supporting evidence (update, minor bump) |
| A case returns rows the agent cannot reason over | fix the query output (raw events, declared fields) |
| The hypothesis itself was wrong | rewrite it under a new id, or delete; Wazuh ids stay allocated |
| New telemetry becomes available | revisit `skipped.yaml` and the blocked targets |

A template is deleted only when its hypothesis is wrong or fully duplicated, never because an
upstream rule disappeared.
