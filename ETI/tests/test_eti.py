from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import yaml

from eti.corroborate import corroborate
from eti.fetch import (CONNECT_TIMEOUT, FeedResult, Item, _client, canonical_url,
                       fetch_one, parse_feed)
from eti.pipeline import OUTPUT_COLUMNS, run
from eti.score import load_scoring, reliability, score
from eti.signals import extract
from eti.sources import Source, load_sources

ETI = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 3, 6, 0, tzinfo=timezone.utc)
CFG = load_scoring(ETI / "scoring.yaml")

RESEARCH = Source("lab", "Lab", "https://lab.test/feed", "https://lab.test", ("threat-research",))
NEWS = Source("news", "News", "https://news.test/feed", "https://news.test", ("threat-news",))
VENDOR = Source("vendor", "Vendor", "https://vendor.test/feed", "https://vendor.test",
                ("ai-soc-vendor",))


def item(source: Source, slug: str, title: str, body: str = "", hours_ago: float | None = 5,
         **kw) -> Item:
    published = None if hours_ago is None else NOW - timedelta(hours=hours_ago)
    return Item(source, f"https://{source.id}.test/{slug}", title, body, published, **kw)


def run_with(tmp_path: Path, results: list[FeedResult], sources: list[Source], *,
             now: datetime = NOW, **kw):
    feeds = tmp_path / "feeds.yaml"
    feeds.write_text("entities:\n" + "".join(
        f"- id: {s.id}\n  name: {s.name}\n  website: {s.website}\n"
        f"  feed: {{url: '{s.url}'}}\n  categories: [{', '.join(s.categories)}]\n"
        f"  status: {s.status}\n" for s in sources))
    wraps = kw.pop("fetcher_wraps", None) or (lambda rs: rs)
    return run(feeds_path=feeds, scoring_path=ETI / "scoring.yaml",
               out_dir=tmp_path / "output", state_dir=tmp_path / "state", now=now,
               fetcher=lambda enabled: wraps(results), **kw)


# -- the shipped configuration -------------------------------------------------

def test_shipped_feed_list_loads_and_every_category_is_scored():
    sources = load_sources(ETI / "security_feeds.yaml")
    assert len(sources) == 133
    assert len({s.id for s in sources}) == 133
    unscored = {c for s in sources for c in s.categories} - set(CFG.category_reliability)
    assert not unscored, f"categories with no reliability in scoring.yaml: {unscored}"
    ids = {s.id for s in sources}
    assert set(CFG.source_reliability) <= ids, "override for a source that is not listed"


def test_weights_must_sum_to_one(tmp_path):
    bad = tmp_path / "scoring.yaml"
    bad.write_text((ETI / "scoring.yaml").read_text().replace("source: 0.30", "source: 0.50"))
    with pytest.raises(ValueError, match="sum to 1.0"):
        load_scoring(bad)


# -- sources and parsing -------------------------------------------------------

def test_publisher_groups_one_organisations_feeds():
    blog = Source("s1", "S1", "https://www.sentinelone.com/blog/feed", "https://sentinelone.com")
    labs = Source("s1l", "S1 Labs", "https://www.sentinelone.com/labs/feed/", "https://sentinelone.com")
    unit42 = Source("u42", "U42", "https://x", "https://unit42.paloaltonetworks.com")
    ncsc = Source("ncsc", "NCSC", "https://x", "https://ncsc.gov.uk")
    assert blog.publisher == labs.publisher == "sentinelone.com"
    assert unit42.publisher == "paloaltonetworks.com"
    assert ncsc.publisher == "ncsc.gov.uk"


def test_canonical_url_drops_tracking_but_keeps_content_parameters():
    assert (canonical_url("https://Example.test/a?utm_source=x&id=7#frag")
            == "https://example.test/a?id=7")


RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>One &amp; only</title><link>https://lab.test/one?utm_medium=rss</link>
<pubDate>Fri, 02 Oct 2026 10:00:00 GMT</pubDate>
<description>&lt;p&gt;Body &lt;b&gt;text&lt;/b&gt;&lt;/p&gt;&lt;script&gt;x()&lt;/script&gt;</description></item>
<item><title>No date</title><link>https://lab.test/two</link></item>
<item><title>No link</title></item>
</channel></rss>"""


def test_parse_feed_strips_markup_and_keeps_undated_entries():
    items = parse_feed(RESEARCH, RSS)
    assert [i.url for i in items] == ["https://lab.test/one", "https://lab.test/two"]
    assert items[0].title == "One & only"
    assert items[0].body == "Body text"
    assert items[0].published == datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc)
    assert items[1].published is None


def test_parse_feed_marks_a_restamped_batch():
    entry = ("<item><title>p{n}</title><link>https://lab.test/{n}</link>"
             "<pubDate>Fri, 02 Oct 2026 10:00:00 GMT</pubDate></item>")
    fresh = ("<item><title>new</title><link>https://lab.test/new</link>"
             "<pubDate>Fri, 02 Oct 2026 11:30:00 GMT</pubDate></item>")
    doc = ("<rss version='2.0'><channel>" + fresh
           + "".join(entry.format(n=n) for n in range(12)) + "</channel></rss>")
    items = parse_feed(RESEARCH, doc.encode())
    assert [i.batch_dated for i in items] == [False] + [True] * 12


# -- signals -------------------------------------------------------------------

def test_signals_read_identifiers_and_artefacts():
    sig = extract(
        "APT29 exploits CVE-2026-12345 in the wild",
        "The loader runs rundll32.exe from C:\\Users\\Public\\x.dll, sets a scheduled task "
        "and beacons to 203[.]0[.]113[.]7 and hxxps://evil[.]example/c2. T1218.011. "
        "Hash 44d88612fea8a8f36de82e1278abb02f. Version 10.0.19041.1 is affected.",
    )
    assert sig.cves == ("CVE-2026-12345",)
    assert sig.attack_ids == ("T1218.011",)
    assert sig.actors == ("APT29",)
    assert {"binary", "win-path", "lolbin", "persistence"} <= set(sig.behaviours)
    assert {"exploited-in-wild", "vulnerability"} <= set(sig.tags)
    # ip, url and hash; the version number must not be read as an address
    assert sig.ioc_count >= 3
    assert "10.0.19041.1" not in " ".join(sig.cves + sig.attack_ids)


def test_a_bare_version_number_is_not_an_indicator():
    assert extract("Update", "Fixed in 10.0.19041.1 and 2.4.6.8 of the agent.").ioc_count == 0


def test_boilerplate_below_the_lede_does_not_make_a_post_relevant():
    filler = "We are proud of our team and our customers. " * 20
    sig = extract("We won a Top Product award", filler + "Stops ransomware, phishing and malware.")
    assert sig.lede_tags == 0 and sig.marketing_hits == 1
    assert score(RESEARCH, sig, 0, CFG).relevance == 0


# -- scoring -------------------------------------------------------------------

def test_reliability_takes_best_category_and_honours_overrides():
    both = Source("x", "X", "u", "w", ("ai-soc-vendor", "threat-research"))
    assert reliability(both, CFG) == CFG.category_reliability["threat-research"]
    assert reliability(Source("ransomware-live", "R", "u", "w", ("vulnerability-exploit",)), CFG) == 0.50
    assert reliability(Source("y", "Y", "u", "w", ("unheard-of",)), CFG) == CFG.default_reliability


def test_score_orders_a_detailed_corroborated_report_above_marketing():
    rich = extract("Threat actor exploits CVE-2026-1111 zero-day with new backdoor",
                   "powershell and rundll32.exe, persistence via scheduled task, LSASS dump, "
                   "C2 at 198[.]51[.]100[.]9, hxxp://bad[.]test, 44d88612fea8a8f36de82e1278abb02f")
    fluff = extract("Announcing our webinar on AI SOC ROI", "Register now for the podcast.")
    top = score(RESEARCH, rich, 3, CFG)
    bottom = score(VENDOR, fluff, 0, CFG)
    assert top.band == "high" and bottom.band == "low"
    assert top.confidence > 80 and bottom.confidence < 20
    # each extra publisher raises the score, up to the last step
    by_n = [score(NEWS, rich, n, CFG).confidence for n in range(6)]
    assert by_n == sorted(by_n) and by_n[3] == by_n[5] > by_n[0]


# -- corroboration -------------------------------------------------------------

def _others(items):
    sig = {i.key: extract(i.title, i.body) for i in items}
    return corroborate(items, sig, threshold=CFG.similarity_threshold,
                       cve_roundup_limit=CFG.cve_roundup_limit)


def test_shared_cve_corroborates_but_a_roundup_does_not():
    a = item(RESEARCH, "a", "Acme gateway flaw CVE-2026-2222 analysed")
    b = item(NEWS, "b", "Patch now: CVE-2026-2222 under attack")
    roundup = item(VENDOR, "r", "Monthly patch roundup",
                   " ".join(f"CVE-2026-{n}" for n in range(2218, 2230)))
    others = _others([a, b, roundup])
    assert others[a.key] == ["news"] and others[b.key] == ["lab"]
    assert others[roundup.key] == []


def test_similar_headlines_corroborate_and_unrelated_ones_do_not():
    filler = [item(Source(f"f{n}", "F", "u", f"https://f{n}.test"), "x",
                   f"Quarterly report number {n} on {topic}")
              for n, topic in enumerate(["cloud spend", "hiring", "compliance audits",
                                         "browser updates", "password managers"])]
    a = item(RESEARCH, "a", "Police dismantle KillSec ransomware gang, arrest teenager")
    b = item(NEWS, "b", "KillSec ransomware gang dismantled as police arrest suspected leader")
    c = item(VENDOR, "c", "Ransomware attack hits regional hospital network")
    others = _others([a, b, c, *filler])
    assert others[a.key] == ["news"] and others[b.key] == ["lab"]
    assert others[c.key] == []


def test_two_feeds_of_one_publisher_are_not_corroboration():
    blog = Source("blog", "B", "u", "https://www.acme.test")
    labs = Source("labs", "L", "u", "https://labs.acme.test")
    a = item(blog, "a", "CVE-2026-3333 in Widget")
    b = item(labs, "b", "Deep dive: CVE-2026-3333")
    others = _others([a, b])
    assert others[a.key] == [] and others[b.key] == []


# -- the run -------------------------------------------------------------------

def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_run_writes_a_datetime_named_csv_sorted_by_confidence(tmp_path):
    results = [
        FeedResult(RESEARCH, True, items=[
            item(RESEARCH, "a", "Backdoor exploits CVE-2026-4444", "rundll32.exe and powershell"),
            item(RESEARCH, "old", "Old post about malware", hours_ago=24 * 30),
        ]),
        FeedResult(NEWS, True, items=[item(NEWS, "b", "CVE-2026-4444 exploited in the wild")]),
        FeedResult(VENDOR, False, error="http 403"),
    ]
    report = run_with(tmp_path, results, [RESEARCH, NEWS, VENDOR])

    assert report.path == tmp_path / "output" / "2026-10-03T060000Z.csv"
    rows = read_csv(report.path)
    assert tuple(rows[0].keys()) == OUTPUT_COLUMNS
    assert [r["source_id"] for r in rows] == ["lab", "news"]          # the old post is not news
    assert [int(r["confidence"]) for r in rows] == sorted(
        (int(r["confidence"]) for r in rows), reverse=True)
    assert rows[0]["corroborated_by"] == "news" and rows[0]["cves"] == "CVE-2026-4444"
    assert rows[0]["age_hours"] == "5.0"

    feeds = {r["source_id"]: r for r in read_csv(tmp_path / "state" / "feeds.csv")}
    assert feeds["vendor"]["status"] == "failed" and feeds["vendor"]["fail_streak"] == "1"
    assert feeds["lab"]["fail_streak"] == "0" and feeds["lab"]["entries"] == "2"


def test_second_run_reports_only_what_is_new_and_counts_the_streak(tmp_path):
    first = item(RESEARCH, "a", "Backdoor exploits CVE-2026-4444")
    run_with(tmp_path, [FeedResult(RESEARCH, True, items=[first]),
                        FeedResult(NEWS, False, error="http 500")], [RESEARCH, NEWS])

    later = NOW + timedelta(days=1)
    second = item(NEWS, "b", "CVE-2026-4444 exploited in the wild", hours_ago=-20)
    report = run_with(tmp_path, [FeedResult(RESEARCH, True, items=[first]),
                                 FeedResult(NEWS, True, items=[second])],
                      [RESEARCH, NEWS], now=later)

    assert [r["source_id"] for r in report.rows] == ["news"]
    # yesterday's item is not repeated, but still corroborates today's
    assert report.rows[0]["corroborated_by"] == "lab"
    feeds = {r["source_id"]: r for r in read_csv(tmp_path / "state" / "feeds.csv")}
    assert feeds["news"]["fail_streak"] == "0"

    third = run_with(tmp_path, [FeedResult(RESEARCH, False, error="http 500"),
                                FeedResult(NEWS, True, items=[second])],
                     [RESEARCH, NEWS], now=later + timedelta(days=1))
    assert third.rows == []
    assert read_csv(third.path) == []                     # header-only file still written
    feeds = {r["source_id"]: r for r in read_csv(tmp_path / "state" / "feeds.csv")}
    assert feeds["lab"]["fail_streak"] == "1" and feeds["lab"]["last_ok"] == "2026-10-04"


def test_undated_and_batch_backlog_is_baselined_then_reported_when_new(tmp_path):
    backlog = [item(RESEARCH, "undated", "Malware notes", hours_ago=None),
               item(RESEARCH, "batch", "Restamped malware post", batch_dated=True),
               item(RESEARCH, "future", "Malware from the future", hours_ago=-24 * 60)]
    report = run_with(tmp_path, [FeedResult(RESEARCH, True, items=backlog)], [RESEARCH])
    assert report.rows == []                               # first sight: nothing to compare with

    fresh = [item(RESEARCH, "undated2", "New undated malware notes", hours_ago=None),
             item(RESEARCH, "future2", "More malware from the future", hours_ago=-24 * 60)]
    report = run_with(tmp_path, [FeedResult(RESEARCH, True, items=backlog + fresh)],
                      [RESEARCH], now=NOW + timedelta(days=1))
    notes = {r["url"].rsplit("/", 1)[1]: r["notes"] for r in report.rows}
    assert set(notes) == {"undated2", "future2"}
    assert notes["undated2"] == "undated" and notes["future2"].startswith("future-dated")
    assert all(r["published_utc"] == "" for r in report.rows)


def test_run_aborts_and_writes_nothing_when_most_feeds_fail(tmp_path):
    results = [FeedResult(RESEARCH, False, error="ConnectError"),
               FeedResult(NEWS, False, error="ConnectError"),
               FeedResult(VENDOR, True, items=[item(VENDOR, "a", "Malware")])]
    report = run_with(tmp_path, results, [RESEARCH, NEWS, VENDOR])
    assert report.aborted and report.path is None
    assert not (tmp_path / "output").exists() and not (tmp_path / "state").exists()


def test_same_url_from_two_feeds_is_one_row_under_the_more_reliable(tmp_path):
    shared = "https://acme.test/post"
    a = Item(VENDOR, shared, "Backdoor analysis", "", NOW - timedelta(hours=2))
    b = Item(RESEARCH, shared, "Backdoor analysis", "", NOW - timedelta(hours=2))
    report = run_with(tmp_path, [FeedResult(VENDOR, True, items=[a]),
                                 FeedResult(RESEARCH, True, items=[b])], [VENDOR, RESEARCH])
    assert [r["source_id"] for r in report.rows] == ["lab"]


def test_unverified_source_is_skipped_visibly_and_formula_titles_are_defused(tmp_path):
    paused = Source("paused", "Paused", "https://paused.test/feed", "https://paused.test", (),
                    status="broken")
    results = [FeedResult(RESEARCH, True, items=[item(RESEARCH, "a", "=HYPERLINK(\"x\") malware")])]
    report = run_with(tmp_path, results, [RESEARCH, paused])
    assert report.rows[0]["title"].startswith("'=")
    feeds = {r["source_id"]: r for r in read_csv(tmp_path / "state" / "feeds.csv")}
    assert feeds["paused"]["status"] == "skipped"


def test_no_state_run_can_be_repeated(tmp_path):
    results = [FeedResult(RESEARCH, True, items=[item(RESEARCH, "a", "Backdoor found")])]
    for _ in range(2):
        report = run_with(tmp_path, results, [RESEARCH], write_state=False)
        assert len(report.rows) == 1
    assert not (tmp_path / "state").exists()


# -- template drafts -----------------------------------------------------------

DRAFT_LEAD = ("Exploited Fortinet flaw CVE-2026-104286 drops a web shell",
              "Attackers chain CVE-2026-104286 to write a web shell. APT29 is "
              "suspected. Hash a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f6789a "
              "and T1505.003 are named.")


def draft_run(tmp_path, **kw):
    """A run over one high-scoring, well-corroborated lead, with drafting on."""
    title, body = DRAFT_LEAD
    results = [FeedResult(s, True, items=[Item(s, f"https://{s.id}.test/lead", title, body,
                                               NOW - timedelta(hours=2))])
               for s in (RESEARCH, NEWS, VENDOR)]
    return run_with(tmp_path, results, [RESEARCH, NEWS, VENDOR],
                    drafts_dir=tmp_path / "templates", **kw)


def test_draft_is_written_for_the_lead_and_carries_what_the_feed_supports(tmp_path):
    report = draft_run(tmp_path)
    assert len(report.drafts) == 1
    path = Path(report.drafts[0]["path"])
    assert path.parent.name == NOW.date().isoformat()
    assert path.name.startswith("ETI-20261003-001-")

    doc = yaml.safe_load(path.read_text())
    assert doc["type"] == "detection-draft" and doc["status"] == "draft"
    assert doc["id"] == report.drafts[0]["draft_id"] == path.stem.lower()
    assert doc["lead"]["band"] == "high"
    assert doc["signals"]["cves"] == ["CVE-2026-104286"]
    # read off the text, never resolved against the STIX bundle
    assert doc["signals"]["attack_ids_mentioned"] == ["T1505.003"]
    # the three things a feed cannot answer are left open, not guessed
    assert doc["mitre"]["techniques"] == [] and doc["query"] == []
    assert doc["hypothesis"]["statement"] == "TODO"


def test_a_lead_is_drafted_once_however_often_it_is_seen(tmp_path):
    first = draft_run(tmp_path)
    assert len(first.drafts) == 1
    drafted = read_csv(tmp_path / "state" / "drafted.csv")
    assert [r["draft_id"] for r in drafted] == [first.drafts[0]["draft_id"]]

    # the same lead, a day later: still new to seen.csv's window, already drafted
    again = draft_run(tmp_path)
    assert again.drafts == []
    assert len(list((tmp_path / "templates").rglob("ETI-*.yaml"))) == 1


def test_only_the_requested_bands_earn_a_draft(tmp_path):
    report = draft_run(tmp_path, draft_bands=("low",))
    assert report.rows[0]["band"] == "high"
    assert report.drafts == []


def test_drafting_is_off_when_no_directory_is_given(tmp_path):
    title, body = DRAFT_LEAD
    results = [FeedResult(RESEARCH, True, items=[item(RESEARCH, "a", title, body)])]
    report = run_with(tmp_path, results, [RESEARCH])
    assert report.drafts == [] and not (tmp_path / "templates").exists()


def test_second_run_of_a_day_continues_the_numbering(tmp_path):
    first = draft_run(tmp_path)
    assert first.drafts[0]["draft_id"].startswith("eti-20261003-001-")

    # an unrelated lead on the same day: numbering continues rather than restarting.
    # One publisher alone does not reach `high`, so the band is widened for this run.
    other = Item(RESEARCH, "https://lab.test/other",
                 "Rclone exfiltration to Mega from a file server",
                 "An operator staged rclone.exe and copied shares to Mega.",
                 NOW - timedelta(hours=1))
    second = run_with(tmp_path, [FeedResult(RESEARCH, True, items=[other])], [RESEARCH],
                      drafts_dir=tmp_path / "templates",
                      draft_bands=("high", "medium", "low"))
    assert len(second.drafts) == 1
    assert second.drafts[0]["draft_id"].startswith("eti-20261003-002-")


def test_retellings_of_one_story_collapse_into_the_best_scoring_lead(tmp_path):
    report = draft_run(tmp_path)
    # three publishers, one story: three rows in the CSV, one piece of work
    assert len(report.rows) == 3
    assert len(report.drafts) == 1
    kept = report.drafts[0]["url"]
    doc = yaml.safe_load(Path(report.drafts[0]["path"]).read_text())
    assert doc["lead"]["url"] == kept
    assert doc["lead"]["other_publishers"] >= 2
    assert doc["lead"]["corroborated_by"], "the draft records who else carried it"


def test_slug_drops_filler_and_stays_short():
    from eti.draft import draft_name, slugify
    assert slugify("The new CISA Advisory on a Fortinet Flaw") == "cisa-advisory-fortinet-flaw"
    assert slugify("!!! ???") == "untitled"
    assert len(slugify("word " * 40)) <= 48
    assert draft_name("2026-10-03", 7, "x") == "ETI-20261003-007-x"


# -- fetching: the cost of a dead host -----------------------------------------

class _Resp:
    def __init__(self, status: int, content: bytes = RSS):
        self.status_code, self.content = status, content


class _Client:
    """Stands in for httpx.Client. Each scripted entry is raised or returned in turn."""

    def __init__(self, *scripted):
        self.scripted, self.calls = list(scripted), 0

    def get(self, url):
        self.calls += 1
        step = self.scripted.pop(0) if self.scripted else _Resp(200)
        if isinstance(step, Exception):
            raise step
        return step

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_a_host_that_will_not_connect_is_tried_once(): 
    """The whole run used to wait two full timeouts for one dead feed."""
    for exc in (httpx.ConnectTimeout("no"), httpx.ConnectError("no")):
        client = _Client(exc, exc)
        result = fetch_one(client, RESEARCH)
        assert client.calls == 1, f"{type(exc).__name__} must not be retried"
        assert not result.ok and result.error == type(exc).__name__


def test_a_failure_mid_flight_is_retried_once():
    """Reached the host and it went wrong on the way back: often transient."""
    client = _Client(httpx.ReadTimeout("slow"), _Resp(200))
    result = fetch_one(client, RESEARCH)
    assert client.calls == 2 and result.ok

    server_error = _Client(_Resp(503), _Resp(200))
    assert fetch_one(server_error, RESEARCH).ok and server_error.calls == 2


def test_a_refusal_is_final():
    client = _Client(_Resp(403))
    result = fetch_one(client, RESEARCH)
    assert client.calls == 1 and result.error == "http 403"


def test_connect_timeout_is_shorter_than_the_read_timeout():
    with _client(workers=4, timeout=25.0) as client:
        assert client.timeout.connect == CONNECT_TIMEOUT
        assert client.timeout.read == 25.0
    # a timeout tighter than the connect budget still wins
    with _client(workers=4, timeout=2.0) as client:
        assert client.timeout.connect == 2.0


def test_an_empty_feed_is_told_from_a_blocked_one_without_a_second_parse(monkeypatch):
    import eti.fetch as fetch_mod
    calls = {"n": 0}
    real = fetch_mod.feedparser.parse

    def counted(content):
        calls["n"] += 1
        return real(content)

    monkeypatch.setattr(fetch_mod.feedparser, "parse", counted)
    empty = b"<?xml version='1.0'?><rss version='2.0'><channel><title>t</title></channel></rss>"
    result = fetch_one(_Client(_Resp(200, empty)), RESEARCH)
    assert result.error == "feed is valid but empty"
    assert fetch_one(_Client(_Resp(200, b"<html>bot check</html>")), RESEARCH).error == \
        "not a feed (blocked, or moved)"
    assert calls["n"] == 2, "one parse per fetch, not two"


def test_fetch_all_restores_the_order_it_was_given(monkeypatch):
    """Completion order is the network's business; output order must not be."""
    import eti.fetch as fetch_mod
    order = [VENDOR, RESEARCH, NEWS]
    monkeypatch.setattr(fetch_mod, "_client", lambda *a, **k: _Client())
    monkeypatch.setattr(fetch_mod, "fetch_one",
                        lambda client, source: FeedResult(source, True, items=[]))
    assert [r.source.id for r in fetch_mod.fetch_all(order, workers=3)] == \
        [s.id for s in order]


def test_in_window_items_are_scored_as_their_feed_lands(tmp_path):
    """The overlap: a streaming fetcher must give the same answer as a list."""
    items = [item(RESEARCH, f"a{n}", f"Backdoor {n} dropped by a web shell") for n in range(5)]
    results = [FeedResult(RESEARCH, True, items=items)]
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    listed = run_with(a, results, [RESEARCH])
    streamed = run_with(b, results, [RESEARCH], fetcher_wraps=lambda rs: iter(rs))
    assert [r["url"] for r in listed.rows] == [r["url"] for r in streamed.rows]
    assert [r["confidence"] for r in listed.rows] == [r["confidence"] for r in streamed.rows]
