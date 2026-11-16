"""Statistics: ping the selected devices in parallel and build the table."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from . import config
from .discovery import Device
from .pinger import PingResult, ping_host

# Single source of column names, shared by GUI, console and reports so the
# terminology is identical everywhere.
TABLE_HEADERS = ("Hostname", "IP Address", "Average Latency (ms)",
                 "Maximum Latency (ms)", "Minimum Latency (ms)",
                 "Packet Loss (%)", "Status")


@dataclass
class DeviceStats:
    """One row of the statistics table."""

    hostname: str
    ip: str
    sent: int
    received: int
    loss_pct: float
    avg_ms: Optional[float]
    max_ms: Optional[float]
    min_ms: Optional[float]
    jitter_ms: Optional[float]
    mac: Optional[str] = None

    @property
    def unreachable(self) -> bool:
        """[DOC] a device with 100 % packet loss is unreachable."""
        return self.loss_pct >= config.UNREACHABLE_LOSS_PCT

    @property
    def high_loss(self) -> bool:
        """Weak connectivity: loss >= 20 % but the device still answers."""
        return not self.unreachable and self.loss_pct >= config.WEAK_LOSS_PCT

    @property
    def status(self) -> str:
        return "Unreachable" if self.unreachable else "Online"

    def as_row(self) -> tuple:
        """Values in ``TABLE_HEADERS`` order ("N/A" when no reply)."""
        na = lambda v: "N/A" if v is None else v
        return (self.hostname, self.ip, na(self.avg_ms), na(self.max_ms),
                na(self.min_ms), self.loss_pct, self.status)


def stats_from_ping(result: PingResult, mac: Optional[str] = None) -> DeviceStats:
    return DeviceStats(
        hostname=result.hostname, ip=result.ip, sent=result.sent,
        received=result.received, loss_pct=result.loss_pct,
        avg_ms=result.avg_ms, max_ms=result.max_ms, min_ms=result.min_ms,
        jitter_ms=result.jitter_ms, mac=mac)


def measure_devices(devices: Sequence[Device], count: int = config.PING_COUNT,
                    progress: Optional[Callable[[int, int], None]] = None
                    ) -> List[DeviceStats]:
    """Ping only the given (user-selected) devices concurrently.

    Results keep the order of ``devices``.
    """
    devices = list(devices)
    if not devices:
        return []
    done = {"n": 0}

    def work(device: Device) -> DeviceStats:
        result = ping_host(device.ip, count=count, hostname=device.hostname)
        done["n"] += 1
        if progress:
            progress(done["n"], len(devices))
        return stats_from_ping(result, device.mac)

    with ThreadPoolExecutor(max_workers=config.MEASURE_WORKERS) as pool:
        return list(pool.map(work, devices))
