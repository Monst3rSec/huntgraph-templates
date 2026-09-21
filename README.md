# huntgraph-templates

Agentic threat-hunting **detection knowledge**, expressed as YAML, derived from MITRE
ATT&CK Enterprise and queried against CrowdStrike NG-SIEM (with Wazuh rules where they
port).

A file here is not an alert rule. A rule fires the same query everywhere and hands you
the false positives. These files answer a different question:

> What evidence should an agent collect to decide whether an observed behaviour
> represents meaningful security risk?

The chain every file follows:

```
MITRE TTP -> attacker behaviour -> hunting hypothesis -> observable telemetry
          -> query -> evidence -> risk logic -> verdict
```

## The consumer decides everything

huntgraph is a threat-hunting **agent**, not a SIEM dashboard. It runs a query, reads what
comes back, and reasons to a verdict it has to explain. So:

- anything the agent needs must be in the query result — it cannot see the console;
- it cannot ask a follow-up of a result set that has already been aggregated away;
- the file must carry the reasoning, not just the match, because the verdict must be
  explained.

A detection rule optimises for precision at fire time; this corpus optimises for
sufficiency at reasoning time. Most mistakes here are a rule-writer's instinct applied to an
agent's input. Three decisions follow:

- **One file, one hypothesis.** T1218.011 has one file for a DLL loaded from a
  user-writable path and another for script run through a protocol handler. A file covering
  "everything rundll32 does" can match but cannot produce an explainable answer.
- **A hit is not a verdict.** Evidence is split into `required`, `supporting` and
  `contradicting`, and risk is composed, never asserted. The contradicting bucket is what
  stops an agent rediscovering the same benign backup job in every environment.
- **Honest gaps beat fake coverage.** A technique whose only observable is telemetry this
  deployment cannot collect is reported as blocked, not approximated.

## Layout

Everything lives under `hunt/`, filed by **category** — what the hunt is about — using
Elastic's [prebuilt-rule domains](https://www.elastic.co/docs/reference/security/prebuilt-rules):
cloud, containers, email, endpoint, identity, kubernetes, llm, network, saas, unspecified,
web. Each category holds two kinds of content side by side:

```
hunt/
└── endpoint/
    ├── README.md                                   what is here, generated
    ├── T1218-system-binary-proxy-execution/        huntgraph templates (validated)
    │   └── T1218.011-rundll32/
    │       ├── rundll32-user-writable-dll.yaml
    │       └── rundll32-script-protocol-handler.yaml
    └── sigma/windows/…                             SigmaHQ rules (unmodified, reference only)
```

Below the category, the MITRE technique and sub-technique are carried by the directory and
the behaviour by the filename. Ids are stable: `hg-<platform>-<behaviour>-<mitre-id>`, e.g.
`hg-win-rundll32-user-writable-dll-t1218-011`, survives rewrites of its description and
query — only a change of hypothesis justifies a new id. Which technique family belongs in
which category is set out in [CLAUDE.md](CLAUDE.md#categories).

```
hunt/                            templates and upstream rules, by category
schema/detection.schema.json     the structural contract
ruleset/                         Wazuh field map and rule-id allocations
skipped.yaml                     targets deliberately not covered, and why
tools/attack_extract.py          the only sanctioned source of MITRE facts
tools/validate.py                five-layer contract enforcement
tools/test_validator.py          injected defects, each must be caught
tools/coverage.py, export_csv.py coverage: task.md and coverage.csv
tools/stats.py                   stats.md
tools/import_sigma.py            SigmaHQ rules into hunt/*/sigma/, tracker/sigma_tracker.md
tools/track_sources.py           Splunk and Elastic triage: tracker/splunk_tracker.md, tracker/elk_tracker.md
```

## Authority

MITRE facts are never written from memory. They come from the Enterprise ATT&CK STIX bundle
via `tools/attack_extract.py` — technique ids, tactics, platforms, detection strategies,
analytics, log sources, data components and procedure examples — and every one in a file
must survive a check against it. The validator has already caught a fabricated data
component that was plausible, adjacent to the truth, and wrong.

```bash
python3 tools/attack_extract.py T1218.011              # everything MITRE says
python3 tools/attack_extract.py --tactic stealth --list # enumerate a tactic
```

Current bundle: **Enterprise ATT&CK v19.2**. v19 renamed Defense Evasion to **Stealth
(TA0005)**, split out **Defense Impairment (TA0112)**, and replaced the data-source model
with `Detection Strategy (DET) -> Analytic (AN) -> log source -> data component`, which is
the chain `mitre:` records.

## File anatomy

Top-level keys, in this order, and no others:

```yaml
type: detection          # constant
id:                      # hg-<platform>-<behaviour>-<mitre-id>
version:                 # semver, bumped on meaningful change
info:                    # name, description, severity, author, tags, references
mitre:                   # tactics, techniques, sub_techniques, detection_strategies,
                         # analytics, platforms, data_sources, data_components
hypothesis:              # statement, attacker_behavior, legitimate_behavior, risk_indicator
requires:                # platforms, connectors, logs[{source, event_types, fields}]
query:                   # a CrowdStrike CQL block, and a Wazuh block where rules port
evidence:                # required, supporting, contradicting,
                         # risk_logic, verdict, false_positive
```

**`hypothesis:`** names one specific attacker behaviour, always paired with the legitimate
behaviour that produces similar telemetry. If you cannot name the legitimate twin, the
hypothesis is not finished.

**`evidence:`** — every item says what it `indicates:`, because the agent reasons over that
field, not the prose. **`risk_logic:` / `verdict:`** compose it:

```
encoded command                                        -> interesting
encoded command + unusual parent                       -> suspicious
encoded command + unusual parent + network activity    -> high risk
```

`mitre.data_components` records what MITRE says the analytic produces; `requires.logs`
records what this hunt actually collects. They can legitimately disagree — for DCSync the
domain controller sees the object access and the endpoint only ever sees the tooling.

## Queries

Every template carries a **CrowdStrike CQL** block; a large share also carry a **Wazuh**
block, with rule ids allocated from `ruleset/wazuh-id-allocations.yaml` and field names from
`ruleset/field-map.yaml`. A CQL case with no Wazuh rule is listed in `not_portable` with the
reason. Other dialects (KQL, SPL, EQL, Sigma) are reserved and rejected if they leak into a
CQL block.

A case returns **raw events** by default: it filters the stream to the behaviour and stops,
so every field reaches the agent. It aggregates only when the aggregation *is* the
hypothesis — a join of two event streams, or a count threshold such as "at breadth". The
rules are in [CLAUDE.md](CLAUDE.md#query-output-policy); current counts are in
[stats.md](stats.md).

Several templates key on **host role** rather than command content: MSBuild, InstallUtil and
local compilation mean nothing on an engineering workstation and a lot on a finance
endpoint. Those depend on asset groups being accurate.

## Validating

```bash
pip install -r tools/requirements.txt
python3 tools/validate.py --strict   # the contract; warnings fail too
python3 tools/test_validator.py      # prove the validator still catches defects
```

Five layers run per file. L1 short-circuits; the rest all run so one pass reports everything
wrong with a template.

| Layer | Checks |
|---|---|
| **L1 structure** | parses; conforms to `schema/detection.schema.json`; unknown keys are errors |
| **L2 mitre** | every ATT&CK id exists, and the relationships the file asserts are the ones MITRE publishes — technique↔tactic, sub↔parent, DET↔technique, AN↔DET, platform↔technique, DC↔analytic |
| **L3 evidence** | evidence ids unique; `risk_logic` and `verdict` reference only real ids; escalation tiers include the required evidence and never cite contradicting evidence; every evidence field is declared in `requires.logs` for every connector |
| **L4 query** | CQL only in CQL blocks; the event stream is constrained to declared event types; every declared field reaches a result row, and every declared source is read by some case; Wazuh blocks well-formed and id-allocated |
| **L5 convention** | path is `hunt/<category>/<technique>/[<sub-technique>/]<behaviour>.yaml`; id ends with its most specific MITRE id; ids unique across the corpus |

`test_validator.py` injects known defects into a good file and asserts the right layer
catches each one. A validator nobody tests is indistinguishable from no validator — and when
it once produced a false positive, the mutation tests are what made narrowing the rule
distinguishable from disabling it.

## What the telemetry cannot see

Coverage by tactic, and the targets blocked on missing telemetry, are in [task.md](task.md).
The shape of the gaps matters more than the counts:

- **Module Load, Process Access, OS API Execution** are not collected. The whole T1055
  process-injection family sits behind them. A command-line approximation of DLL injection
  detects nothing while looking like coverage, so these stay blocked rather than faked.
  Confirming the NG-SIEM schema for module loads and process handle access would convert the
  largest block of remaining work from impossible to routine.
- **There is no generic file-write event.** `PeFileWritten`, `NewExecutableWritten` and
  `NewScriptWritten` fire on executables and scripts only. A document, archive, image or
  mailbox file being written produces nothing, so where a template appears to hunt those it
  is really hunting the command that wrote them. There is no file-read or file-deletion event
  either.
- **Registry events are writes only.** Reading a key — much of Discovery — is visible only
  through the command that did it, never a compiled program reading directly.
- **Some things are visible only once.** Browser extensions (T1176.001) and virtual instances
  (T1564.006) can be caught at installation and not afterwards.
- **Some hunts depend on history.** Lateral movement and deployment-tool templates (T1021.001,
  T1021.006, T1072) return the support desk and the patch cycle without a populated baseline.

`skipped.yaml` records targets deliberately not covered, each with the reason and the
telemetry change that would make it writable. The bar is narrow — not "this is hard", but
"the only observable is one we cannot collect" — and a recorded skip is what keeps a
decision from reading as a backlog item once its author moves on.

## Upstream rules

Third-party rules are reference material for authoring, never templates:

| Source | Held how | Tracker |
|---|---|---|
| SigmaHQ `rules-threat-hunting/windows` | stored unmodified in `hunt/<category>/sigma/`, pinned to one commit | [sigma_tracker.md](tracker/sigma_tracker.md) |
| Splunk security content | triaged, not stored | [splunk_tracker.md](tracker/splunk_tracker.md) |
| Elastic detection rules | triaged, not stored | [elk_tracker.md](tracker/elk_tracker.md) |

Upstream rules with no ATT&CK mapping are listed in `unclassified-threat-check/`. Turning an
upstream rule into a template is authoring, not porting: the behaviour is rewritten as a
hypothesis with its own evidence and CQL, and it often turns out to be a hunt the corpus
already has. See [CLAUDE.md](CLAUDE.md#upstream-rule-ingestion).

## Generated files

Never edit these by hand — rerun the tool.

| File | Tool | What it is |
|---|---|---|
| [stats.md](stats.md) | `tools/stats.py` | what the corpus contains, and an index of every technique family by category |
| [task.md](task.md) | `tools/coverage.py --markdown` | coverage by tactic and priority, and what is blocked |
| [coverage.csv](coverage.csv) | `tools/export_csv.py` | the whole Enterprise matrix, one row per tactic-technique, with status |
| [sigma_tracker.md](tracker/sigma_tracker.md), `hunt/*/sigma/`, `hunt/*/README.md` | `tools/import_sigma.py` | Sigma rules by category — Category, TTP, Rule, Description, Path |
| [splunk_tracker.md](tracker/splunk_tracker.md), [elk_tracker.md](tracker/elk_tracker.md), `unclassified-threat-check/` | `tools/track_sources.py` | every upstream rule with its routing decision |

## The iteration loop

The format is validated in batches, so defects are found while they are cheap to fix:

1. **Enumerate** a tactic with `attack_extract.py --tactic <name> --list`.
2. **Select** techniques with genuinely distinct telemetry; skip those with no observable
   evidence — a forced detection is worse than none.
3. **Extract** ground truth per technique. Nothing enters a YAML that is not in that output
   or the cited references.
4. **Author** one file per hypothesis, in the right category.
5. **Validate** with `validate.py --strict` and `test_validator.py`.
6. **Amend the contract** when a batch exposes a gap, then re-validate the whole corpus
   before the next batch, so drift cannot accumulate.

## Contributing

- Write the hypothesis for a human analyst. If it only restates the query, it is not pulling
  its weight.
- Prefer behaviour over indicators. `FileName = powershell.exe` is not a hunt; process plus
  parent plus command line plus path plus network activity is.
- Put real environmental exceptions in `false_positive:` — that is what stops an agent
  rediscovering the same benign pattern everywhere.
- Do not invent event types or fields. If the telemetry for a behaviour is uncertain, build on
  telemetry that is certain.
- Cases within a `query:` block must be meaningfully different hunts, not spelling variants.

Working with an agent? [CLAUDE.md](CLAUDE.md) (mirrored in [AGENTS.md](AGENTS.md)) holds the
operating rules.

## Licence

Apache-2.0, except the Sigma rules under `hunt/*/sigma/`, which remain under the
[Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) — see
[hunt/README.md](hunt/README.md).
