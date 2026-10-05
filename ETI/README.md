# ETI — emerging threat intel, scored

Reads the 133 feeds in [security_feeds.yaml](security_feeds.yaml) once a day, works out
what is new, scores each item for how much weight a SecOps or hunt team should put on it
as a lead, writes one CSV named for the run time, and opens a hunt-template draft for
each lead that earned one:

```
output/2026-10-03T051700Z.csv
templates/2026-10-03/ETI-20261003-001-fortinet-security-advisory-av26-989.yaml
```

No model, no submodule, three dependencies. A **sub-project**: it has its own venv, its
own `requirements.txt`, its own tests and its own entrypoint, it imports nothing from the
repo around it, and nothing in that repo imports it. `tools/validate.py` does not walk
`ETI/`, and `ETI/run.sh` never touches `hunt/`.

## Run it

```bash
./run.sh                       # fetch, score, write the CSV and the drafts, update state/
./run.sh --no-state            # same, leaving state/ alone, so it can be repeated
./run.sh --no-drafts           # the CSV only, no template drafts
./run.sh --draft-band high --draft-band medium   # widen what earns a draft
./run.sh --draft-limit 5       # at most five drafts from this run
./run.sh test                  # the tests; no network
```

In CI it is [.github/workflows/eti-daily.yml](../.github/workflows/eti-daily.yml):
daily at 05:17 UTC, or on demand from the Actions tab with the window, the draft bands
and whether to commit as inputs. The job runs the tests, then the aggregation; it commits
`output/`, `state/` and `templates/` back to the branch, uploads the day's CSV and drafts
as an artifact, and puts the top items, the new drafts and the failed feeds in the run
summary.

That workflow file is the only part of ETI that is not under `ETI/`, because GitHub reads
workflows only from `.github/workflows`. It is kept thin on purpose: it calls `run.sh` and
decides nothing. A push made with `GITHUB_TOKEN` does not start another workflow run, so
the daily commit cannot loop into `validate`.

## The score

`confidence` is 0–100, from four components that are each written to the CSV beside it:

| Component | Weight | What it measures |
|---|---:|---|
| `score_source` | 30 | Who published it. By feed category, with per-source overrides. |
| `score_corroboration` | 20 | How many *other publishers* carry the same story. |
| `score_specificity` | 30 | What there is to hunt on: CVEs, indicators, host artefacts, ATT&CK ids, named actors. |
| `score_relevance` | 20 | Whether the headline and lede are about a threat, less what reads as marketing. |

Bands: `high` ≥ 65, `medium` ≥ 50, else `low`. `medium` sits just above what a reliable
source writing on-topic reaches with nothing else, so it always means at least one
concrete hook. Every weight, threshold and reliability figure is in
[scoring.yaml](scoring.yaml) with its reason; change them there.

What the number is not:

- **Not severity.** A well-reported, detailed write-up of a minor bug outscores a
  one-line notice of a critical one.
- **Not verification.** Corroboration counts reporting. Five outlets rewriting one
  vendor's post count as five.
- **Not a reading of the article.** Only the feed is fetched. `text_basis` says whether
  the publisher put the `full` text, a `summary` or just a `title` in it — a low
  specificity score on a `summary` row says little about the article behind it.

## Template drafts

A feed entry is a lead, not a behaviour. It gives a headline and a summary; it does not
give the parent-child relationship or the command line a hunt is built on. So a run opens
a **draft**, never a template: the `lead:` and `signals:` blocks carry everything the feed
actually supports, and `info`, `mitre`, `hypothesis`, `requires`, `query` and `evidence`
are left `TODO` for whoever reads the article.

Drafts are named `ETI-<yyyymmdd>-<nnn>-<slug>.yaml` under the run's date, so one always
traces back to the day that produced it. Default is the `high` band only; retellings of
one story collapse into the best-scoring lead, and a URL already drafted is recorded in
`state/drafted.csv` and not drafted again. [templates/README.md](templates/README.md) has
the notation, what each block means and how to finish one.

Nothing in `templates/` is validated, and none of it belongs in `hunt/` until its MITRE
block has been through `tools/attack_extract.py` and it passes
`python3 tools/validate.py --strict`.

## Columns

| Column | Meaning |
|---|---|
| `confidence`, `band` | The score and its band. Rows are sorted by score, newest first within a score. |
| `published_utc`, `age_hours` | From the feed. Blank when the date is missing or unusable; see `notes`. |
| `source_id`, `source`, `categories` | From the feed list. |
| `title`, `url` | As published. URLs have tracking parameters removed. |
| `tags` | Subjects found in the text: `exploited-in-wild`, `zero-day`, `poc-public`, `ransomware`, `malware`, `phishing`, `supply-chain`, `vulnerability`, `intrusion`. |
| `cves` | CVE ids in the text. |
| `attack_ids_mentioned` | ATT&CK ids that literally appear in the text. Not validated against the STIX bundle and never inferred from prose. |
| `actors` | Actor designators in the text (APT29, UNC1234, Storm-0558, "… Typhoon"). |
| `ioc_count` | Distinct hashes, defanged IPs, domains and URLs. |
| `behaviours` | Kinds of host or network artefact named: `binary`, `registry`, `lolbin`, `persistence`, `credential`, … |
| `other_publishers`, `corroborated_by` | How many other publishers carry the story, and which sources. |
| `score_*` | The four components, 0–1. |
| `text_basis` | `title`, `summary` or `full`: how much text the feed supplied. |
| `notes` | `undated`, `future-dated <date>` or `batch-dated`. |

## What counts as new

An item is reported once. `state/seen.csv` holds every item a run has observed, and an
item is emitted when it is not in there and was published within the last 72 hours
(`--window-hours`). The first run therefore reports three days; every later run reports
what appeared since the one before.

Three kinds of date cannot be trusted to place an item in that window: a missing one, one
more than a day in the future, and one shared to the second by ten or more entries of
the same feed (some site builders restamp every post each time the site is published).
Those items are new only relative to what the source showed last time. On a source's
first run there is no last time, so its backlog is recorded as seen and not reported.

## Speed

A run is about **9 seconds** for 133 feeds, and it is gated by the single slowest host
rather than by how much is in flight. Three things keep it there:

| | |
|---|---|
| **The connect timeout is separate** | 5s to complete a handshake, the full `--timeout` to send bytes back. A host that answers deserves patience; one that will not answer at all deserves none. |
| **A connect failure is not retried** | Retrying a host that is down buys nothing and costs a second timeout. Only a failure *mid-flight* — a read timeout, a 5xx — is retried, once. |
| **48 feeds in flight** (`--workers`) | They are I/O; the box is idle throughout. Past this the wall is one slow feed, not the queue. |

Signals are extracted from each in-window item **as its feed lands**, so that work
happens in the gaps while the slow hosts are still in flight rather than after them.

These numbers are worth re-checking if a run starts creeping up: one feed that stops
answering used to be enough to double it. `state/feeds.csv` names it.

## Feed health

`state/feeds.csv` has a row per source with `status`, `error` and `fail_streak`. The
streak is the column to watch: one failure is the internet, ten in a row is a feed that
has moved or started blocking the runner. Feeds are fetched with an honest user agent
and a blocked feed is left blocked and reported, not retried under a browser's name.

If fewer than half the feeds can be read, the run exits non-zero and writes nothing,
because the problem is then the runner and not the sources.

An entity whose `status` in the feed list is anything but `verified` is not fetched and
shows as `skipped`. That is the way to turn a source off.

## Layout

```
security_feeds.yaml   the sources
scoring.yaml          weights, bands, reliability, matching thresholds
eti/
  sources.py          the feed list, and who counts as one publisher
  fetch.py            one GET per feed; RSS, Atom and RDF into items; streams results
  signals.py          CVEs, indicators, artefacts, tags, read off the text
  corroborate.py      who else is carrying the same story
  score.py            the four components and the total
  state.py            seen.csv and feeds.csv
  draft.py            a lead becomes a template draft
  pipeline.py         one run
output/               one CSV per run, committed
state/                seen.csv, feeds.csv, committed
```
