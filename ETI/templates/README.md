# ETI/templates — hunt template drafts

One draft per lead that the daily run judged worth the work. A draft is **not** a
detection template and never goes to `hunt/` as it stands.

```
ETI/templates/<run date>/ETI-<yyyymmdd>-<nnn>-<slug>.yaml
ETI/templates/2026-10-03/ETI-20261003-001-fortinet-security-advisory-av26-989.yaml
```

| Part | Meaning |
|---|---|
| `ETI-` | Where it came from. Nothing under `hunt/` carries this prefix. |
| `20261003` | The run that produced it. The parent directory repeats it as `2026-10-03`. |
| `001` | Position within that day, by confidence. `001` is the day's strongest lead. |
| `<slug>` | The headline, stripped of filler, six words at most. |

The `id:` inside is the filename lowercased — `eti-20261003-001-fortinet-security-advisory-av26-989`.
It deliberately does **not** match the corpus pattern `hg-<platform>-<behaviour>-<mitre-id>`,
because a draft has no verified technique to end on. Getting one is the work.

## What a draft contains

Three blocks, and the split between them is the whole point:

- **`lead:`** — what the feed said. Title, URL, publisher, score, who else carried it.
  Facts about the *publication*, not about the threat.
- **`signals:`** — strings found in the feed text. CVEs, actor names, tags, behaviours
  and any ATT&CK ids that literally appeared in the prose. Nothing inferred.
- **everything else** — `info`, `mitre`, `hypothesis`, `requires`, `query`, `evidence`,
  all `TODO`. These are the shape of a real template so that filling them in is the
  entire job, but a feed entry cannot answer any of them.

`signals.attack_ids_mentioned` is the one to be careful with. Those ids were read off a
blog post. They have **not** been through `tools/attack_extract.py`, and hard invariant 1
says a MITRE fact that has not is not a fact. Re-derive every one before it reaches
`mitre:`.

## Finishing one

1. **Read the article.** `lead.text_basis` says what the feed gave — `title`, `summary`
   or `full`. None of them is the article.
2. **Find the behaviour**, not the tool and not the CVE. What does the host actually do
   that telemetry can see? If the answer is "nothing a command line would show", stop.
3. **Check the telemetry.** Evidence that needs Module Load, Process Access or OS API
   Execution is not collectable here. Record it in `skipped.yaml` and drop the draft —
   an approximation that detects nothing while looking like coverage is worse than a gap.
4. **Check `hunt/` first.** A fresh report on an old behaviour is an update to the
   template that already holds it — bump its `version`, add the URL to
   `info.references` — not a second template under a new id.
5. **Resolve the MITRE block** with `python3 tools/attack_extract.py <id>`. Never from
   memory, never from the article, never from `attack_ids_mentioned`.
6. **Write the query** as hand-written CQL returning raw events.
7. **Promote it**: move the file to `hunt/<category>/<Txxxx-slug>/[<Txxxx.yyy-slug>/]<behaviour>.yaml`,
   give it an `hg-…` id, delete the `status`, `generated`, `lead`, `signals` and
   `authoring` keys, and make `python3 tools/validate.py --strict` pass. Until it does,
   it stays here.

Dropping a draft is a normal outcome. Most intel is not huntable on this telemetry, and
an honest empty day beats a template that detects nothing.

## What gets drafted

Only leads in the bands the run was given — `high` by default, which on a typical day is
a handful. Two limits worth knowing:

- **Retellings collapse.** Ten outlets rewriting one vendor post are one piece of work.
  Within a run, rows that corroborate each other fold into the best-scoring one, which
  keeps `corroborated_by` so you can still see who else carried it. On one real day this
  took 29 `high` rows down to 10 drafts.
- **It only collapses within a run.** A fresh article tomorrow on the same story arrives
  as a new URL and gets its own draft. That is usually what you want — new reporting on
  a known story is often the part worth reading — but it is the reason to check `hunt/`
  and the existing drafts before starting.

A lead is drafted once per URL; `ETI/state/drafted.csv` is the record.

## These files are not validated

`tools/validate.py` only walks `hunt/`. Nothing here is checked by L1–L5, nothing counts
toward coverage or stats, and `type: detection-draft` keeps a draft from being mistaken
for a template if one is ever copied by accident.
