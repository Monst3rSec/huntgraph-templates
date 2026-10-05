"""Which other publishers are carrying the same story.

Matching is pairwise and deliberately not transitive. Clustering would be the obvious
shape, but one Patch Tuesday roundup shares a CVE with fifty otherwise unrelated items
and a union-find merges all of them into a single "story" that everything corroborates.
Asking, per item, "who else reports this" cannot chain like that.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict

from .fetch import Item
from .signals import Signals

_WORD = re.compile(r"[a-z0-9][a-z0-9.\-]*[a-z0-9]")
_STOP = frozenset(
    "the and for with from that this are was were has have had its their into over new "
    "how why what when who you your our out not but can more than about after before "
    "says said will could may now via amid using used use also been being they them".split()
)
_TITLE_WEIGHT = 3      # a headline names the story; a summary surrounds it with boilerplate
_SUMMARY_CHARS = 400


def _terms(item: Item) -> Counter[str]:
    def words(text: str) -> list[str]:
        return [w for w in _WORD.findall(text.lower()) if len(w) > 2 and w not in _STOP]

    counts: Counter[str] = Counter()
    for word in words(item.title):
        counts[word] += _TITLE_WEIGHT
    for word in words(item.body[:_SUMMARY_CHARS]):
        counts[word] += 1
    return counts


def corroborate(items: list[Item], signals: dict[str, Signals], *,
                threshold: float, cve_roundup_limit: int) -> dict[str, list[str]]:
    """Map each item's key to the ids of sources, from other publishers, that match it.

    One source id per publisher: a vendor's blog and its lab feed are one voice.
    """
    n = len(items)
    matches: list[set[int]] = [set() for _ in range(n)]

    # Shared CVE. Roundups are excluded on both sides — an item listing thirty CVEs is
    # not a report *about* any one of them.
    by_cve: dict[str, list[int]] = defaultdict(list)
    for i, item in enumerate(items):
        cves = signals[item.key].cves
        if 0 < len(cves) <= cve_roundup_limit:
            for cve in cves:
                by_cve[cve].append(i)
    for group in by_cve.values():
        for i in group:
            matches[i].update(j for j in group if j != i)

    # Similar wording. TF-IDF so that "ransomware" and "attack", which every item
    # shares, count for nothing and a product or malware name counts for a lot.
    vectors = [_terms(item) for item in items]
    df: Counter[str] = Counter()
    for vec in vectors:
        df.update(vec.keys())
    postings: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for i, vec in enumerate(vectors):
        weighted = {t: tf * math.log(1 + n / df[t]) for t, tf in vec.items()}
        norm = math.sqrt(sum(w * w for w in weighted.values())) or 1.0
        for term, w in weighted.items():
            postings[term].append((i, w / norm))

    # Terms in more than a tenth of the pool cannot identify a story and are most of
    # the cost of the join, so they are left out of it.
    max_df = max(25, n // 10)
    dots: dict[tuple[int, int], float] = defaultdict(float)
    for term, posting in postings.items():
        if len(posting) < 2 or len(posting) > max_df:
            continue
        for a in range(len(posting)):
            i, wi = posting[a]
            for b in range(a + 1, len(posting)):
                j, wj = posting[b]
                dots[(i, j)] += wi * wj
    for (i, j), score in dots.items():
        if score >= threshold:
            matches[i].add(j)
            matches[j].add(i)

    out: dict[str, list[str]] = {}
    for i, item in enumerate(items):
        by_publisher: dict[str, str] = {}
        for j in matches[i]:
            other = items[j].source
            if other.publisher != item.source.publisher:
                by_publisher.setdefault(other.publisher, other.id)
        out[item.key] = sorted(by_publisher.values())
    return out
