"""Network health score, 0-100 (report, "Network health score").

    reachability  up to 40 pts  = 40 x (devices that respond / devices tested)
    packet loss   up to 30 pts  = 30 x (1 - min(avg loss, 30 %) / 30 %)
    latency       up to 30 pts  = 30 at <= 20 ms, linear to 0 at 200 ms

Rating: Excellent 90-100, Good 75-89, Fair 60-74, Poor < 60. This is a
project-defined indicator, not an industry-standard rating.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from . import config
from .stats import DeviceStats


@dataclass
class HealthScore:
    score: int
    rating: str
    reachability_pts: float
    loss_pts: float
    latency_pts: float
    avg_loss_pct: float
    avg_latency_ms: Optional[float]
    responding: int
    tested: int


def rating_for(score: int) -> str:
    for minimum, label in config.RATING_BANDS:
        if score >= minimum:
            return label
    return "Poor"


def compute_health(stats: Iterable[DeviceStats]) -> Optional[HealthScore]:
    """Score the measured devices, or ``None`` if nothing was measured.

    * Average packet loss is the mean over *all* tested devices.
    * Average latency is the mean of the per-device averages of devices that
      replied at least once; with no replies the latency component is 0.
    """
    stats = list(stats)
    if not stats:
        return None
    tested = len(stats)
    responding = [s for s in stats if not s.unreachable]

    reach = config.REACHABILITY_POINTS * len(responding) / tested

    avg_loss = sum(s.loss_pct for s in stats) / tested
    loss = config.LOSS_POINTS * (1 - min(avg_loss, config.LOSS_ZERO_AT_PCT)
                                 / config.LOSS_ZERO_AT_PCT)

    latencies = [s.avg_ms for s in responding if s.avg_ms is not None]
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        span = config.LATENCY_ZERO_AT_MS - config.LATENCY_FULL_AT_MS
        frac = 1 - (avg_latency - config.LATENCY_FULL_AT_MS) / span
        lat = config.LATENCY_POINTS * max(0.0, min(1.0, frac))
    else:
        avg_latency, lat = None, 0.0

    score = int(round(reach + loss + lat))            # rating uses the shown integer
    return HealthScore(
        score=score, rating=rating_for(score),
        reachability_pts=round(reach, 1), loss_pts=round(loss, 1),
        latency_pts=round(lat, 1), avg_loss_pct=round(avg_loss, 1),
        avg_latency_ms=None if avg_latency is None else round(avg_latency, 2),
        responding=len(responding), tested=tested)
