"""The confidence score.

Four components, each 0..1, combined by the weights in `scoring.yaml`. Nothing here is
learned and nothing is hidden: the same inputs always give the same number, and the
components are written out beside the total.

What the number means: how much weight a SecOps or hunt team should put on an item
*as a lead* — a reliable publisher, reported elsewhere, with detail that can be turned
into a query, about an actual threat. It is not a severity and not a probability that
the claim is true.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .signals import Signals
from .sources import Source


@dataclass(frozen=True)
class Scoring:
    weights: dict[str, float]
    bands: dict[str, float]
    category_reliability: dict[str, float]
    default_reliability: float
    source_reliability: dict[str, float] = field(default_factory=dict)
    corroboration_steps: tuple[float, ...] = (0.0, 0.5, 0.8, 1.0)
    similarity_threshold: float = 0.30
    cve_roundup_limit: int = 5


@dataclass(frozen=True)
class Score:
    source: float
    corroboration: float
    specificity: float
    relevance: float
    confidence: int
    band: str


def load_scoring(path: Path) -> Scoring:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    weights = {k: float(v) for k, v in doc["weights"].items()}
    expected = {"source", "corroboration", "specificity", "relevance"}
    if set(weights) != expected:
        raise ValueError(f"{path}: weights must be exactly {sorted(expected)}")
    # Weights that do not sum to 1 still produce a number, just not one out of 100 —
    # and the bands would then silently mean something else.
    if abs(sum(weights.values()) - 1.0) > 1e-6:
        raise ValueError(f"{path}: weights must sum to 1.0, got {sum(weights.values()):.3f}")
    return Scoring(
        weights=weights,
        bands={k: float(v) for k, v in doc["bands"].items()},
        category_reliability={k: float(v) for k, v in doc["category_reliability"].items()},
        default_reliability=float(doc.get("default_reliability", 0.4)),
        source_reliability={k: float(v) for k, v in (doc.get("source_reliability") or {}).items()},
        corroboration_steps=tuple(float(v) for v in doc.get("corroboration_steps", (0, 0.5, 0.8, 1))),
        similarity_threshold=float(doc.get("similarity_threshold", 0.30)),
        cve_roundup_limit=int(doc.get("cve_roundup_limit", 5)),
    )


def reliability(source: Source, cfg: Scoring) -> float:
    if source.id in cfg.source_reliability:
        return cfg.source_reliability[source.id]
    known = [cfg.category_reliability[c] for c in source.categories
             if c in cfg.category_reliability]
    return max(known) if known else cfg.default_reliability


def _specificity(sig: Signals) -> float:
    """How much there is to hunt on. The shares sum to 1."""
    return (
        0.25 * bool(sig.cves)
        + 0.25 * min(sig.ioc_count, 3) / 3
        + 0.30 * min(len(sig.behaviours), 4) / 4
        + 0.10 * bool(sig.attack_ids)
        + 0.10 * bool(sig.actors)
    )


def _relevance(sig: Signals) -> float:
    """Threat subject matter in the headline and lede, less what reads as marketing.

    Two distinct subjects is full marks. A lede is short, and a research post that names
    a backdoor and the intrusion it was used in has said what it is about.
    """
    threat = min(sig.lede_tags, 2) / 2
    return max(0.0, min(1.0, threat - 0.25 * min(sig.marketing_hits, 2)))


def score(source: Source, sig: Signals, other_publishers: int, cfg: Scoring) -> Score:
    steps = cfg.corroboration_steps
    parts = {
        "source": reliability(source, cfg),
        "corroboration": steps[min(other_publishers, len(steps) - 1)],
        "specificity": _specificity(sig),
        "relevance": _relevance(sig),
    }
    confidence = round(100 * sum(cfg.weights[k] * v for k, v in parts.items()))
    band = ("high" if confidence >= cfg.bands["high"]
            else "medium" if confidence >= cfg.bands["medium"] else "low")
    return Score(confidence=confidence, band=band, **{k: round(v, 2) for k, v in parts.items()})
