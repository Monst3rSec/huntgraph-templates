# hunt

Every template, filed by **category** (what the hunt is about) using Elastic's
[prebuilt-rule domains](https://www.elastic.co/docs/reference/security/prebuilt-rules):
`cloud` · `containers` · `email` · `endpoint` · `identity` · `kubernetes` · `llm` ·
`network` · `saas` · `unspecified` · `web`. A category folder exists only once it holds a
template.

```
hunt/<category>/<Txxxx-slug>/[<Txxxx.yyy-slug>/]<behaviour>.yaml
```

The category is the first directory, the MITRE technique and sub-technique the next, and the
behaviour the filename; L5 of `tools/validate.py` rejects any other layout. Which technique
family belongs in which category is in [AGENTS.md](../AGENTS.md#categories), and
[stats.md](../stats.md) indexes every family with its template count.

Upstream rules (Splunk, Elastic, Sigma) are never stored here. They are triaged at their
source by `tools/track_sources.py` into [tracker/](../tracker/), and a rule enters `hunt/`
only by being rewritten as a template.
