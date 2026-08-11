# Project

## What this is

A corpus of **agentic threat-hunting detection knowledge**: structured YAML that tells a
hunting agent what evidence to collect and how to reason about it, derived from MITRE
ATT&CK Enterprise and queryable against CrowdStrike NG-SIEM.

These are not alert rules. A rule fires the same query everywhere and hands you the false
positives. A file here answers a different question:

> What evidence should an agent collect to decide whether an observed behaviour
> represents meaningful security risk?

## Why it is shaped this way

Three decisions determine everything else.

**One file, one hypothesis.** A single sub-technique often produces several files. T1218.011
has one for a DLL loaded from a user-writable path and another for script executed through a
protocol handler, because those are different behaviours with different evidence and
different verdicts. A file covering "everything rundll32 does" could not produce an
explainable answer.

**Evidence is split three ways.** `required` establishes the behaviour, `supporting` raises
confidence, `contradicting` lowers it. A query hit is never a verdict:

```
encoded command                                      -> interesting
encoded command + unusual parent                     -> suspicious
encoded command + unusual parent + network activity  -> high risk
```

The contradicting bucket is what stops an agent rediscovering the same benign pattern in
every environment. Most files spend as much effort on it as on the detection.

**Nothing about MITRE is written from memory.** `tools/attack_extract.py` reads the ATT&CK
STIX bundle, and every technique id, tactic, detection strategy, analytic and data component
in a file must survive a check against it. That is not defensive tidiness — the validator has
already caught a fabricated data component that was plausible, adjacent to the truth, and
wrong.

## Layout

```
techniques/T1218-system-binary-proxy-execution/
└── T1218.011-rundll32/
    ├── rundll32-user-writable-dll.yaml
    └── rundll32-script-protocol-handler.yaml

schema/detection.schema.json     the structural contract
tools/attack_extract.py          the only sanctioned source of MITRE facts
tools/validate.py                five-layer contract enforcement
tools/test_validator.py          25 injected defects, asserts each is caught
tools/coverage.py                what is done, what is left, what is blocked
```

The directory carries the technique; the filename carries the behaviour. Ids are stable —
`hg-win-rundll32-user-writable-dll-t1218-011` survives rewrites of its description and query,
and only a change of hypothesis justifies a new one.

## The validator is the point

```bash
pip install -r tools/requirements.txt
python3 tools/validate.py --strict
python3 tools/test_validator.py
```

| Layer | Catches |
|---|---|
| L1 structure | schema conformance; unknown keys are errors |
| L2 mitre | every id exists, and the relationships a file asserts are the ones MITRE publishes |
| L3 evidence | referential integrity between evidence, risk logic and verdict; every field declared |
| L4 query | CQL only; no SPL, KQL, EQL, SQL or Sigma; declared event types actually used |
| L5 convention | directory encodes the technique; ids unique and correctly suffixed |

`test_validator.py` injects 25 known defects and asserts the right layer catches each. That
matters more than it sounds: when the validator once produced a *false* positive, the
mutation tests are what made narrowing the rule distinguishable from disabling it.

## What it cannot do

Roughly 40% of the remaining Priority 1 targets cannot be given an honest hypothesis with
process, file and network telemetry. Their analytics rest on Module Load, Process Access and
OS API Execution — the whole T1055 injection family among them.

```bash
python3 tools/coverage.py --priority 1 --blocked
```

Those are reported rather than skipped. A command-line approximation of DLL injection detects
nothing while looking like coverage, which is the failure this contract exists to prevent.

Two other honest limits, stated in the files themselves:

- **Browser extensions (T1176.001)** and **virtual instances (T1564.006)** can be caught at
  installation and not afterwards. Once running, the activity is opaque to endpoint telemetry.
- **Lateral movement and deployment-tool templates** (T1021.001, T1021.006, T1072) depend
  entirely on baseline history. Without a populated window they return the support desk and
  the patch cycle.

## Conventions worth knowing before reading the files

- Queries are CrowdStrike CQL. The schema is multi-platform by construction; other dialects
  are reserved and deliberately not generated.
- `mitre.data_components` records what MITRE says the analytic produces. `requires.logs`
  records what this hunt actually collects. They can legitimately disagree — DCSync is the
  clearest case, where the domain controller sees the object access and the endpoint only
  ever sees the tooling.
- Several templates key on **host role** rather than command content: MSBuild, InstallUtil and
  local compilation are meaningless on an engineering workstation and significant on a finance
  endpoint. Those depend on asset groups being accurate.

## Status

See [task.md](task.md), which is generated:

```bash
python3 tools/coverage.py --markdown > task.md
```

## Licence

Apache-2.0
