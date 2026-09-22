# huntgraph-templates

Agentic threat-hunting **detection knowledge**, expressed as YAML, derived from MITRE
ATT&CK Enterprise and queried against CrowdStrike NG-SIEM (with Wazuh rules where they
port). Each file is one hunting hypothesis for the huntgraph agent: what to query, what
evidence comes back, and how to reason from it to an explainable verdict.

```
MITRE TTP -> attacker behaviour -> hunting hypothesis -> observable telemetry
          -> query -> evidence -> risk logic -> verdict
```

| Read | For |
|---|---|
| [intent.md](intent.md) | why this exists, goals, non-goals, principles |
| [adlc.md](adlc.md) | the Agent Development Life Cycle: intake to commit, with the gate for each phase |
| [AGENTS.md](AGENTS.md) | the operating rules: invariants, categories, triage, query output policy (`CLAUDE.md` imports it) |
| [stats.md](stats.md) | what the corpus contains, and an index of every technique family |

## Quick start

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r tools/requirements.txt
python3 tools/validate.py --strict   # the contract; warnings fail too
python3 tools/test_validator.py      # prove the validator still catches defects
```

## Layout

```
hunt/<category>/<Txxxx-slug>/[<Txxxx.yyy-slug>/]<behaviour>.yaml   the templates
schema/detection.schema.json     the structural contract
ruleset/                         Wazuh field map and rule-id allocations
skipped.yaml                     targets deliberately not covered, and why
tools/                           validator, ATT&CK extractor, coverage, stats, upstream triage
tracker/                         every upstream rule (Splunk, Elastic, Sigma) and its outcome
unclassified-threat-check/       upstream rules with no ATT&CK mapping, staged
```

Categories are Elastic's prebuilt-rule domains; which technique family goes where is in
[AGENTS.md](AGENTS.md#categories). Ids are stable: `hg-<platform>-<behaviour>-<mitre-id>`,
e.g. `hg-win-rundll32-user-writable-dll-t1218-011`.

MITRE facts come only from the Enterprise ATT&CK STIX bundle via `tools/attack_extract.py`.
Current bundle: **Enterprise ATT&CK v19.2**, which renamed Defense Evasion to **Stealth
(TA0005)**, split out **Defense Impairment (TA0112)**, and replaced the data-source model with
`Detection Strategy (DET) -> Analytic (AN) -> log source -> data component`, the chain
`mitre:` records.

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

## Generated files

Never edit these by hand — rerun the tool.

| File | Tool |
|---|---|
| [stats.md](stats.md) | `tools/stats.py` |
| [task.md](task.md) | `tools/coverage.py --markdown` |
| [coverage.csv](coverage.csv) | `tools/export_csv.py` |
| [tracker/](tracker/), [unclassified-threat-check/](unclassified-threat-check/) | `tools/track_sources.py` |

## Licence

Apache-2.0.
