# huntgraph-templates

Hypothesis templates for [HuntGraph](https://github.com/Monst3rSec/HuntGraph).

A template is not a detection rule. A rule fires the same query in every environment
and hands you the false positives. A HuntGraph template describes a **hypothesis** —
why an adversary would produce a signal — plus the queries needed to learn what normal
looks like *here* before hunting for the abnormal.

HuntGraph clones this repo on startup and pulls on every subsequent run.

## Layout

```
credential-access/    TA0006 — getting hold of secrets
defense-evasion/      TA0005 — avoiding or blinding controls
stealth/              masquerading, anti-forensics, covert channels
```

## Template anatomy

Two sections make a template adaptive rather than static:

**`baseline:`** — queries run *before* the hunt, to learn the environment. Their results
feed the declared `signals`, and never become findings themselves.

**`hunt.tunable:`** — the only keys the agent may rewrite when adapting the hunt to an
environment. Everything else, including the detection logic, is immutable at runtime.
This boundary is the safety property of the whole system: an agent that could rewrite
the query body could quietly delete the part that catches the attacker.

```yaml
id: hg-win-lsass-memory-access          # lowercase kebab-case, globally unique
info:
  name: Unusual process opening LSASS memory
  severity: critical                     # info | low | medium | high | critical
  tags: [credential-access, lsass, windows]
  mitre:
    tactics: [TA0006]                    # TA0001 form
    techniques: [T1003.001]              # T1234 or T1234.001 form

hypothesis: |
  Why an adversary produces this signal, and why the naive version of the
  detection fails. This grounds the agent's reasoning — write it for a human.

requires:
  platforms: [windows]
  data_sources: [process_access]
  connectors: [crowdstrike-ngsiem]       # must include hunt.connector

baseline:
  window: 30d
  queries:
    - id: lsass_accessors
      description: Which processes open LSASS here, and how often.
      query: |
        ...
  signals: [value_distribution, per_host_frequency, first_seen]

hunt:
  connector: crowdstrike-ngsiem
  window: 7d
  max_results: 2000
  query: |
    ...
    {{tuning_filters}}                   # required if `tunable` is non-empty
  tunable:
    exclude_source_images: []
    min_rarity: 0.01

triage:
  fields: [ComputerName, UserName, SourceImageFileName]
  escalate_when: |
    Natural-language criteria, evaluated against the baseline.
  false_positive_hints:
    - What benign activity looks like this, and why.

output:
  finding_title: Unusual process opened LSASS memory on {{ComputerName}}
```

### Available baseline signals

`rare_command_lines`, `per_host_frequency`, `parent_process_distribution`,
`first_seen`, `last_seen`, `field_cardinality`, `value_distribution`,
`peer_comparison`.

Declaring a signal outside this set is a load-time error — a template must never
silently depend on analysis that will not happen.

## Contributing

Validate before opening a PR:

```bash
huntgraph template validate --path .
```

Rules the loader enforces, and why:

- **Unknown fields are rejected.** A typo should fail loudly, not silently disable a hunt.
- **`tunable` requires a `{{tuning_filters}}` placeholder** (and vice versa). Otherwise
  tuning appears to succeed while changing nothing.
- **`hunt.connector` must appear in `requires.connectors`.** Catches a template
  retargeted at a new backend with stale requirements.
- **Windows are `<number><unit>`** — `m`, `h`, `d`, `w`. No bare numbers.

Content guidance:

- Write `hypothesis` for a human analyst. If it only restates the query, it is not
  pulling its weight.
- Put real environmental exceptions in `false_positive_hints`. This is what stops the
  agent from re-discovering the same benign pattern in every environment.
- Prefer behaviour over indicators. Tool names and hashes age out in weeks; the reason
  the behaviour is necessary to the adversary does not.
- `baseline` is optional, but a template without one cannot be tuned to an environment
  and will behave like a static rule.

## Licence

Apache-2.0
