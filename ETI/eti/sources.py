"""The feed list.

`security_feeds.yaml` is read as it is published — entities with a feed URL, categories
and notes — rather than converted into a second format that would have to be kept in
step with it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

# Second-level suffixes under which a registrable domain has three labels. Only the
# ones the feed list can plausibly contain; this is not a public-suffix list.
_TWO_LABEL_SUFFIXES = {"co.uk", "gov.uk", "ac.uk", "or.jp", "co.jp", "gc.ca",
                       "gouv.fr", "com.au", "gov.au", "europa.eu"}


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    website: str = ""
    categories: tuple[str, ...] = ()
    status: str = "verified"

    @property
    def enabled(self) -> bool:
        return self.status == "verified"

    @property
    def publisher(self) -> str:
        """Who is behind the feed, for counting corroboration.

        Two feeds from one organisation — a vendor's blog and its research lab — are
        one voice, and an item carried by both has not been confirmed by anybody. The
        registrable domain of the website is a cheap, good-enough proxy for that.
        """
        host = (urlparse(self.website or self.url).hostname or self.id).lower()
        labels = host.removeprefix("www.").split(".")
        take = 3 if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES else 2
        return ".".join(labels[-take:])


def load_sources(path: Path) -> list[Source]:
    """Every entity with a feed URL, including ones not marked verified.

    Unverified entities are returned so the run can report them as skipped; dropping
    them here would make a disabled source look the same as one that was never listed.
    """
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    out: list[Source] = []
    seen: set[str] = set()
    for entity in doc.get("entities") or []:
        url = ((entity.get("feed") or {}).get("url") or "").strip()
        sid = str(entity.get("id") or "").strip()
        if not url or not sid:
            continue
        if sid in seen:
            raise ValueError(f"duplicate entity id in {path}: {sid!r}")
        seen.add(sid)
        out.append(
            Source(
                id=sid,
                name=str(entity.get("name") or sid),
                url=url,
                website=str(entity.get("website") or ""),
                categories=tuple(entity.get("categories") or ()),
                status=str(entity.get("status") or "verified"),
            )
        )
    return out
