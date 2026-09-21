# upstream

Third-party detection rules, stored **unmodified** and filed by the telemetry they read.
They are reference material for authoring, not huntgraph templates: `validate.py` does not
scan this directory, and nothing here is converted. A rule becomes a template only by being
rewritten as a hypothesis under `techniques/` — see "Converting is authoring, not porting" in
[CLAUDE.md](../CLAUDE.md).

## Categories

Folders follow Elastic's [prebuilt-rule domains](https://www.elastic.co/docs/reference/security/prebuilt-rules).
A rule is filed by its log source, not its technique: Windows host telemetry is `endpoint`
whatever it detects, and `identity` means an identity provider, not a workstation's own
account events.

`cloud` · `containers` · `email` · `endpoint` · `identity` · `kubernetes` · `llm` ·
`network` · `saas` · `unspecified` · `web`

Inside each, rules sit under their source (`sigma/`), keeping the source's own path.

## Sources

| Source | Imported from | Tracker | Refresh |
|---|---|---|---|
| Sigma | [SigmaHQ/sigma `rules-threat-hunting/windows`](https://github.com/SigmaHQ/sigma/tree/master/rules-threat-hunting/windows), at the commit recorded in the tracker | [sigma_tracker.md](../sigma_tracker.md) | `python3 tools/import_sigma.py [--ref <sha>]` |

Everything under `*/sigma/` and every category `README.md` is generated; rerun the import
rather than editing them.

## Licence

The Sigma rules are © their authors, as named in each file's `author` field, and are
distributed under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
The DRL permits redistribution provided the author attribution and this licence notice are
kept, which is why the files are stored byte-for-byte as published. The rest of this
repository is Apache-2.0; the DRL, not Apache-2.0, governs the files under `*/sigma/`.
