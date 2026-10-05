"""Fetch every feed once and turn its entries into items.

One GET per feed per run, with an honest user agent. A feed that refuses that is
recorded as failed rather than retried under a browser's name: the failure streak in
`state/feeds.csv` is how a blocked source becomes visible, and disguising the client
would hide exactly that.

Only the feed is read. Article pages are not fetched, so an item is scored on what its
publisher chose to put in the feed — which is why the CSV says how much text that was.
"""

from __future__ import annotations

import hashlib
import html
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import feedparser
import httpx

from .sources import Source

USER_AGENT = (
    "eti-aggregator/0.1 (+https://github.com/Monst3rSec/HuntGraph-Emerging-Threats; "
    "daily threat intel digest)"
)
_ACCEPT = "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8"

# A host that cannot complete a TCP handshake in this long is down or dropping us, and
# waiting the full read timeout for it gates the whole run on the worst host in the list.
CONNECT_TIMEOUT = 5.0

# Feeds are I/O: the box is idle the whole time. The ceiling that matters is politeness
# to 133 unrelated hosts, not local capacity.
DEFAULT_WORKERS = 48

# Retried once: something that was reached and went wrong mid-flight, which is often
# transient. A connect failure is not in here on purpose -- the host is down or blocking,
# and a second attempt buys nothing while costing another timeout.
_RETRYABLE = (httpx.ReadTimeout, httpx.WriteTimeout, httpx.ReadError, httpx.WriteError,
              httpx.RemoteProtocolError, httpx.PoolTimeout)

# A feed that lists its whole archive should not make one run arbitrarily slow.
MAX_ENTRIES_PER_FEED = 300
MAX_TEXT_CHARS = 20_000

# Some site builders restamp every entry with the time the site was last published, so
# a two-year-old post arrives dated this morning. One timestamp, to the second, shared
# by this many entries of one feed is a batch, and a batch date cannot say whether an
# item is new.
BATCH_DATE_MIN = 10

# Tracking parameters carry no content and would otherwise defeat dedupe: the same
# article shared from two places is the same article.
_TRACKING_PREFIXES = ("utm_", "mc_", "pk_")
_TRACKING_EXACT = {"fbclid", "gclid", "igshid", "ref", "source", "cmpid"}

_SCRIPT = re.compile(r"<(script|style)\b.*?</\1>", re.S | re.I)
_TAG = re.compile(r"<[^>]+>")
_SPACE = re.compile(r"\s+")


@dataclass
class Item:
    source: Source
    url: str
    title: str
    body: str                      # feed summary or content, tags stripped
    published: datetime | None     # UTC; None when the feed gives no usable date
    batch_dated: bool = False      # shares its timestamp with a batch; see BATCH_DATE_MIN
    key: str = ""

    def __post_init__(self) -> None:
        if not self.key:
            self.key = hashlib.sha1(self.url.encode("utf-8")).hexdigest()[:16]

    @property
    def text(self) -> str:
        return f"{self.title}\n{self.body}"


@dataclass
class FeedResult:
    source: Source
    ok: bool
    error: str = ""
    items: list[Item] = field(default_factory=list)


def canonical_url(url: str) -> str:
    """Normalise a URL enough that the same article hashes the same way.

    Conservative on purpose: case-folding the host and dropping the fragment and
    tracking parameters is safe; stripping a trailing slash or forcing https is not.
    """
    parts = urlparse(url.strip())
    query = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith(_TRACKING_PREFIXES) and k.lower() not in _TRACKING_EXACT
    ]
    return urlunparse((parts.scheme, parts.netloc.lower(), parts.path, parts.params,
                       urlencode(query), ""))


def strip_html(value: str) -> str:
    value = _SCRIPT.sub(" ", value or "")
    value = _TAG.sub(" ", value)
    return _SPACE.sub(" ", html.unescape(value)).strip()


def _as_utc(struct_time) -> datetime | None:
    if not struct_time:
        return None
    try:
        return datetime(*struct_time[:6], tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def parse_feed(source: Source, content: bytes) -> list[Item]:
    """Parse RSS, Atom or RDF into items. See `parse_detail` for the version too."""
    return parse_detail(source, content)[0]


def parse_detail(source: Source, content: bytes) -> tuple[list[Item], str]:
    """Parse once, returning the items and the feed version feedparser recognised.

    feedparser is lenient by design and returns an empty entry list for something that
    is not a feed at all, so the caller judges success by the count, not by the parse.
    The version comes back from the same parse because telling "a real feed that is
    empty" from "an interstitial that answered 200" is worth no second parse of a
    document that can be megabytes.
    """
    parsed = feedparser.parse(content)
    items: list[Item] = []
    seen: set[str] = set()
    for entry in parsed.entries[:MAX_ENTRIES_PER_FEED]:
        link = entry.get("link") or ""
        if not link.startswith("http"):
            guid = entry.get("id") or ""
            link = guid if guid.startswith("http") else ""
        if not link:
            continue
        url = canonical_url(link)
        if url in seen:
            continue
        seen.add(url)

        bodies = [entry.get("summary") or ""]
        bodies += [c.get("value") or "" for c in entry.get("content") or []]
        body = max((strip_html(b) for b in bodies), key=len)[:MAX_TEXT_CHARS]

        items.append(
            Item(
                source=source,
                url=url,
                title=strip_html(entry.get("title") or ""),
                body=body,
                published=_as_utc(entry.get("published_parsed"))
                or _as_utc(entry.get("updated_parsed")),
            )
        )

    stamps = Counter(i.published for i in items if i.published)
    for item in items:
        item.batch_dated = stamps.get(item.published, 0) >= BATCH_DATE_MIN
    return items, parsed.get("version") or ""


def fetch_one(client: httpx.Client, source: Source) -> FeedResult:
    """Fetch and parse one feed. Never raises: one dead source must not end the run."""
    error = ""
    for attempt in range(2):
        try:
            resp = client.get(source.url)
        except httpx.HTTPError as exc:
            error = type(exc).__name__
            # A host that would not connect will not connect a second later. Retrying
            # it is how one dead feed used to cost the run two full timeouts.
            if not isinstance(exc, _RETRYABLE):
                break
            continue
        if resp.status_code >= 500:
            error = f"http {resp.status_code}"
            continue
        if resp.status_code >= 400:
            return FeedResult(source, ok=False, error=f"http {resp.status_code}")
        try:
            items, version = parse_detail(source, resp.content)
        except Exception as exc:  # feedparser on hostile input; keep the run alive
            return FeedResult(source, ok=False, error=f"parse: {type(exc).__name__}")
        if not items:
            # Zero entries is a failure rather than a quiet day: a bot check answering
            # 200 with an interstitial lands here. A real feed that is simply empty is
            # told apart only so the streak says which of the two to go and look at.
            return FeedResult(source, ok=False, error="feed is valid but empty" if version
                              else "not a feed (blocked, or moved)")
        return FeedResult(source, ok=True, items=items)
    return FeedResult(source, ok=False, error=error or "unknown")


def _client(workers: int, timeout: float) -> httpx.Client:
    """One pooled client for the whole run.

    The connect timeout is separate from the read timeout: most of a feed's time is
    waiting for bytes from a host that answered, and that deserves patience, while a
    host that will not answer at all deserves none.
    """
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=min(CONNECT_TIMEOUT, timeout)),
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT, "Accept": _ACCEPT},
        limits=httpx.Limits(max_connections=max(1, workers),
                            max_keepalive_connections=max(1, workers)),
    )


def fetch_stream(sources: list[Source], *, workers: int = DEFAULT_WORKERS,
                 timeout: float = 25.0) -> Iterator[FeedResult]:
    """Yield each feed's result the moment it lands, fastest first.

    The point of yielding rather than returning a list is that the caller can do its own
    work on a feed while the slow ones are still in flight. A run is gated by its worst
    host, and everything that can be done before that host answers should already be
    done by the time it does.
    """
    with _client(workers, timeout) as client:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(fetch_one, client, s): s for s in sources}
            for future in as_completed(futures):
                source = futures[future]
                try:
                    yield future.result()
                except Exception as exc:  # a bug in fetch_one must not end the run
                    yield FeedResult(source, ok=False, error=f"internal: {type(exc).__name__}")


def fetch_all(sources: list[Source], *, workers: int = DEFAULT_WORKERS,
              timeout: float = 25.0) -> list[FeedResult]:
    """Fetch all feeds concurrently, returning results in the order given.

    Completion order is whatever the network decides; the input order is restored here
    so that a run over the same feeds produces the same output whatever the weather.
    """
    done = {r.source.id: r for r in fetch_stream(sources, workers=workers, timeout=timeout)}
    return [done[s.id] for s in sources if s.id in done]
