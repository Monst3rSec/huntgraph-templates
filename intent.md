# Intent

Why this repository exists, what it is for, and what it deliberately is not. When a change
is hard to judge, this is the reference: a change that serves the intent is right even if it
is inconvenient, and a change that works against it is wrong even if it passes the
validator.

## Purpose

huntgraph-templates is the **detection knowledge** consumed by the huntgraph threat-hunting
agent. Each YAML file is one hunting hypothesis: what to query, what evidence the result
carries, and how to reason from that evidence to a verdict the agent can explain.

It answers one question per file:

> What evidence should an agent collect to decide whether an observed behaviour represents
> meaningful security risk?

Every file follows the same chain:

```
MITRE TTP -> attacker behaviour -> hunting hypothesis -> observable telemetry
          -> query -> evidence -> risk logic -> verdict
```

## The consumer decides everything

huntgraph is an **agent**, not a SIEM dashboard. It runs a query, reads what comes back and
reasons to a verdict it has to justify. That has three consequences, and most design choices
in this repository follow from one of them:

- Anything the agent needs must be in the query result. It cannot see the console.
- It cannot ask a follow-up of a result set that has already been aggregated away, so queries
  return raw events by default.
- The file must carry the reasoning, not just the match, because the verdict must be
  explained.

A detection rule optimises for precision at fire time; this corpus optimises for
**sufficiency at reasoning time**. Most mistakes here are a rule-writer's instinct applied to
an agent's input.

## Goals

1. **Explainable verdicts.** Evidence is split into `required`, `supporting` and
   `contradicting`, and risk is composed in `risk_logic` and `verdict`, never asserted by a
   single match.
2. **Ground truth only.** Every MITRE fact is checkable against the pinned Enterprise ATT&CK
   STIX bundle; every event type and field is one the connector actually emits.
3. **Honest coverage.** A technique whose only observable is telemetry this deployment cannot
   collect is reported as blocked or recorded in `skipped.yaml`, never approximated.
4. **One place for every rule.** Ideas from Splunk, Elastic, Sigma, reports or analysts enter
   in one form only, as a validated template, and every upstream rule considered has a
   recorded outcome in `tracker/`.
5. **A contract that enforces itself.** `tools/validate.py` encodes the rules and
   `tools/test_validator.py` proves the validator still catches what it claims to.

## Non-goals

- **Not an alert ruleset.** Nothing here is meant to fire on its own or be tuned for alert
  volume.
- **Not a rule-format converter.** SPL, EQL, KQL, ES|QL and Sigma are never translated
  mechanically or stored; a conversion is a rewrite as a hypothesis.
- **Not maximal coverage.** A forced detection is worse than none. A blocked or skipped
  target is an acceptable, recorded outcome.
- **Not a telemetry wishlist.** Templates are written against what CrowdStrike NG-SIEM (and,
  where rules port, Wazuh) actually collects today.

## Principles

- **One file, one hypothesis.** A file covering "everything rundll32 does" can match but
  cannot produce an explainable answer. If a statement needs "or", it is two files.
- **Name the legitimate twin.** Every hypothesis is paired with the benign behaviour that
  produces similar telemetry. If you cannot name it, the hypothesis is not finished.
- **Behaviour over indicators.** `FileName = powershell.exe` is not a hunt; process, parent,
  command line, path and network activity together are.
- **Stable identity.** A template's id survives rewrites of its prose and query; only a change
  of hypothesis justifies a new id.
- **Generated means generated.** Coverage, statistics and trackers are computed from the files
  on disk and never edited by hand.

## Success looks like

- `validate.py --strict` and `test_validator.py` pass on every commit.
- Every covered ATT&CK target has at least one hypothesis an analyst would recognise as
  distinct and defensible.
- Every uncovered target is either outstanding, blocked on named telemetry, or skipped with a
  written reason.
- The agent's verdicts cite evidence ids from the template, and a benign pattern found once is
  captured as `contradicting` evidence or a `false_positive` so it is not rediscovered.

How the work is carried out is in [adlc.md](adlc.md); the operating rules an agent must follow
are in [AGENTS.md](AGENTS.md).
