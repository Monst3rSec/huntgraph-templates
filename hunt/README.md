# hunt

Every hunt in the repository, filed by **category** — what the hunt is about — using
Elastic's [prebuilt-rule domains](https://www.elastic.co/docs/reference/security/prebuilt-rules):

`cloud` · `containers` · `email` · `endpoint` · `identity` · `kubernetes` · `llm` ·
`network` · `saas` · `unspecified` · `web`

Each category folder holds two kinds of content side by side:

| Folder | What it is | Validated | Licence |
|---|---|---|---|
| `T####-<technique>/[T####.###-<sub-technique>/]<behaviour>.yaml` | huntgraph templates — one hypothesis per file | yes, by `tools/validate.py` | Apache-2.0 |
| `sigma/…` | SigmaHQ threat-hunting rules, stored unmodified | no — reference only | Detection Rule License 1.1 |

Each category's `README.md` says how many of each it holds; [stats.md](../stats.md) indexes
every technique family and [sigma_tracker.md](../tracker/sigma_tracker.md) lists every Sigma rule.
The category mapping for templates is in [CLAUDE.md](../CLAUDE.md#categories).

## Templates

A template lives where its behaviour belongs: traffic on the wire and host-to-host movement
under `network`, accounts and authentication under `identity`, host activity under
`endpoint`, and so on. Below the category the MITRE technique and sub-technique are carried
by the directory and the behaviour by the filename. L5 rejects any other layout.

## Sigma rules

`sigma/` folders hold the rules from
[SigmaHQ/sigma `rules-threat-hunting/windows`](https://github.com/SigmaHQ/sigma/tree/master/rules-threat-hunting/windows),
copied byte-for-byte from the commit recorded in [sigma_tracker.md](../tracker/sigma_tracker.md) and
keeping Sigma's own path below `sigma/`. A Sigma rule is filed by the telemetry it reads —
all of the current ones read Windows host logs, so all sit in `endpoint/sigma/`. They are
material to author from, not templates: `validate.py` and every other tool skip `sigma/`,
and a rule becomes a template only by being rewritten as a hypothesis in a technique folder.

Refresh or re-pin with `python3 tools/import_sigma.py [--ref <sha>]`. It regenerates every
`sigma/` folder, every category `README.md` and the tracker; never edit them by hand.

## Licence

The Sigma rules are © their authors, as named in each file's `author` field, and are
distributed under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
The DRL permits redistribution provided the author attribution and this licence notice are
kept, which is why the files are stored exactly as published. The DRL, not Apache-2.0,
governs every file under `*/sigma/`; the templates and everything else in this repository
are Apache-2.0.
