# huntgraph-templates

Agentic threat-hunting **detection knowledge**, expressed as YAML, derived from MITRE
ATT&CK Enterprise.

A file here is not an alert rule. A rule fires the same query everywhere and hands you
the false positives. These files answer a different question:

> What evidence should an agent collect to decide whether an observed behaviour
> represents meaningful security risk?

The chain every file follows:

```
MITRE TTP -> attacker behaviour -> hunting hypothesis -> observable telemetry
          -> query -> evidence -> risk logic -> verdict
```

**One file = one hypothesis.** A single sub-technique usually produces several files.
A file that tries to cover every behaviour of a technique cannot produce an explainable
verdict, which is the entire point of the format.

## Layout

The MITRE technique and sub-technique are carried by the directory, not by the filename.
The filename is the behaviour.

```
techniques/
└── T1218-system-binary-proxy-execution/
    └── T1218.011-rundll32/
        ├── rundll32-user-writable-dll.yaml
        └── rundll32-script-protocol-handler.yaml
```

Stable ids: `hg-<platform>-<behaviour>-<mitre-id>`, e.g.
`hg-win-rundll32-user-writable-dll-t1218-011`. The id must survive rewrites of the
description and the query — only a change of hypothesis justifies a new id.

## Authority

MITRE facts are never written from memory. They are read from the Enterprise ATT&CK
STIX bundle by `tools/attack_extract.py`, which is the only sanctioned source for
technique ids, tactics, platforms, detection strategies, analytics, log sources, data
components and procedure examples.

```bash
python3 tools/attack_extract.py T1218.011              # everything MITRE says
python3 tools/attack_extract.py --tactic stealth --list # enumerate a tactic
```

Current bundle: **Enterprise ATT&CK v19.2**. Note that v19 renamed Defense Evasion to
**Stealth (TA0005)** and split out **Defense Impairment (TA0112)**; v19 also replaced the
old data-source model with `Detection Strategy (DETxxxx) -> Analytic (ANxxxx) -> log
source -> data component (DCxxxx)`, which is the chain `mitre:` records.

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
query:                   # [{platform: crowdstrike, language: cql, cases: [...]}]
evidence:                # required, supporting, contradicting,
                         # risk_logic, verdict, false_positive
```

Three sections carry the weight:

**`hypothesis:`** — one specific attacker behaviour, not a restatement of the MITRE
description, and always paired with the legitimate behaviour that produces similar
telemetry. If you cannot name the legitimate twin, the hypothesis is not finished.

**`evidence:`** — split into `required` (establishes the behaviour), `supporting`
(raises confidence) and `contradicting` (indicates benign activity). Every item says
what it `indicates:`, because the agent reasons over that field, not over the prose.

**`risk_logic:` / `verdict:`** — a query hit is never a verdict. Risk is a combination:

```
encoded command                                        -> interesting
encoded command + unusual parent                       -> suspicious
encoded command + unusual parent + network activity    -> high risk
```

### Query platforms

The schema is multi-platform by construction, but only CrowdStrike is implemented:

```yaml
query:
  - platform: crowdstrike
    language: cql
```

`microsoft-kql`, `splunk-spl`, `elastic-eql`, `sentinel` and `chronicle` are reserved
and deliberately not generated. The validator rejects foreign dialects leaking into a
CQL block.

## Validating

```bash
pip install -r tools/requirements.txt
python3 tools/validate.py            # whole repo
python3 tools/validate.py --strict   # warnings fail too
python3 tools/test_validator.py      # prove the validator still catches defects
```

Five layers run per file. L1 short-circuits; the rest all run so one pass reports
everything wrong with a template.

| Layer | Checks |
|---|---|
| **L1 structure** | parses; conforms to `schema/detection.schema.json`; unknown keys are errors |
| **L2 mitre** | every ATT&CK id exists, and the relationships the file asserts are the ones MITRE publishes — technique↔tactic, sub↔parent, DET↔technique, AN↔DET, platform↔technique, DC↔analytic; the technique URL is cited |
| **L3 evidence** | evidence ids unique; `risk_logic` and `verdict` reference only real ids; `risk_logic.required` equals `evidence.required`; escalation tiers include the required evidence and never cite contradicting evidence; every evidence field is declared in `requires.logs` |
| **L4 query** | CrowdStrike CQL only; no SPL/KQL/EQL/SQL/Sigma; the event stream is constrained; queries use the declared event types; baselines are complete when required |
| **L5 convention** | directory encodes the technique; id ends with its most specific MITRE id; kebab-case filenames; ids unique across the corpus |

`tools/test_validator.py` injects 24 known defects into a good file and asserts the
right layer catches each one. A validator nobody tests is indistinguishable from no
validator.

## The iteration loop

The format is validated tactic by tactic, in batches, so that defects are found while
the corpus is small enough to fix cheaply.

Each iteration:

1. **Enumerate** the tactic with `attack_extract.py --tactic <name> --list`.
2. **Select** a batch of techniques with genuinely distinct telemetry. Skip techniques
   where no observable evidence exists — a forced detection is worse than none.
3. **Extract** ground truth per technique. Nothing enters a YAML that is not in that
   output or in the cited references.
4. **Author** one file per hypothesis.
5. **Validate** with `validate.py --strict` and `test_validator.py`.
6. **Amend the contract** when a batch exposes a gap — a missing check, an over-strict
   pattern, a schema field that does not carry its weight — then re-run the whole corpus
   against the amended contract before starting the next batch.

Step 6 is the loop. The schema and the validator are expected to change between
iterations; the corpus is re-validated in full each time so drift cannot accumulate.

### Status

Run `python3 tools/coverage.py --priority 1` for the current figure — it is computed
from the corpus, never from this table.

Priority 1 is Execution, Persistence, Privilege Escalation, Stealth, Defense
Impairment, Credential Access and Lateral Movement: **315 unique in-scope leaf
targets**. Priority 2 (Discovery, Collection, Command and Control, Exfiltration) is
declared but not yet worked.

### The reachable remainder is smaller than the remaining count

```bash
python3 tools/coverage.py --priority 1 --blocked
```

**97 of the uncovered Priority 1 targets — around 40% — cannot be given an honest
hypothesis with the telemetry this repo targets.** Their MITRE analytics rest entirely
on data components the CrowdStrike process, file and network events cannot supply:

| Missing component | Techniques it would unblock |
|---|---|
| Module Load | 50 |
| Process Access | 38 |
| OS API Execution | 26 |
| Process Modification | 13 |
| Driver Load | 5 |

The whole T1055 process-injection family sits behind the first three, as do
T1620 Reflective Code Loading, T1129 Shared Modules and T1622 Debugger Evasion.

This is deliberate, not an omission. A command-line approximation of DLL injection
detects nothing while looking like coverage, which is the failure mode the contract
exists to prevent. Confirming the NG-SIEM schema for module loads and process handle
access is worth more than several batches of authoring: it converts the single largest
block of remaining work from impossible to routine.

### Recorded skips

`skipped.yaml` names the targets this project has decided not to cover, each with the
reason and the concrete telemetry change that would make it writable. They appear in
`coverage.csv` with status `skipped` and a `skip_reason` column rather than being
folded into the outstanding count.

The distinction matters more than it looks. Without the register, a deliberate
decision is indistinguishable from a backlog item, so every skip reads as work
someone will get to eventually and the reasoning is lost the moment its author moves
on. An acknowledged blind spot is manageable; the same gap unrecorded is just an
unknown. The bar for entry is narrow — not "this is hard" or "the query would be
noisy", but "the only observable is one we cannot collect".

## Contributing

- Write the hypothesis for a human analyst. If it only restates the query, it is not
  pulling its weight.
- Prefer behaviour over indicators. `FileName = powershell.exe` is not a hunt; process
  plus parent plus command line plus path plus network activity is.
- Put real environmental exceptions in `false_positive:`. This is what stops an agent
  from rediscovering the same benign pattern in every environment.
- Do not invent event types or fields. If CrowdStrike telemetry for a behaviour is
  uncertain, build the hypothesis on telemetry that is certain.
- Cases within a `query:` block must be meaningfully different hunts, not spelling
  variants of one another.

## Licence

Apache-2.0
