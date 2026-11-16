"""Connectivity testing: run the OS ``ping`` utility and compute statistics.

Design (report, "Connectivity testing"):
  * ``-n`` on Windows, ``-c`` on macOS / Linux, platform-specific timeouts.
  * Command execution (``ping_host``) is separate from parsing
    (``parse_ping_output``) so the parser can be tested with sample output.
  * Windows ``time<1ms`` is recorded as 1 ms.
  * Packet loss = requests sent vs. replies received - never the localized
    summary line.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import platform
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from . import config

log = logging.getLogger(__name__)

# "time=12.3 ms", "time<1ms", "zeit=1ms", "time=0,5 ms" (decimal comma).
_RTT_RE = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)
# Only reply lines carry a TTL. Requiring it excludes Windows' summary line
# ("Minimum = 1ms, Maximum = 2ms") and "Destination host unreachable" lines.
_TTL_RE = re.compile(r"ttl\s*=", re.IGNORECASE)


class PingError(Exception):
    """Invalid ping parameters or ping utility unavailable."""


@dataclass
class PingResult:
    """Raw outcome of one multi-request ping test."""

    ip: str
    hostname: str = "Unknown"
    sent: int = 0
    received: int = 0
    rtts_ms: List[float] = field(default_factory=list)

    @property
    def loss_pct(self) -> float:
        """Packet loss % from requests sent and replies received."""
        if self.sent <= 0:
            return 100.0
        return round((self.sent - self.received) / self.sent * 100.0, 1)

    @property
    def min_ms(self) -> Optional[float]:
        return round(min(self.rtts_ms), 2) if self.rtts_ms else None

    @property
    def avg_ms(self) -> Optional[float]:
        return round(sum(self.rtts_ms) / len(self.rtts_ms), 2) if self.rtts_ms else None

    @property
    def max_ms(self) -> Optional[float]:
        return round(max(self.rtts_ms), 2) if self.rtts_ms else None

    @property
    def jitter_ms(self) -> Optional[float]:
        """Mean absolute difference between consecutive replies (needs >= 2).

        The report names jitter but does not define it; this is the usual
        inter-arrival definition (see GAP_ANALYSIS, open decisions).
        """
        if len(self.rtts_ms) < 2:
            return None
        diffs = [abs(b - a) for a, b in zip(self.rtts_ms, self.rtts_ms[1:])]
        return round(sum(diffs) / len(diffs), 2)


def validate_ipv4(value: str) -> str:
    """Return a normalised IPv4 string or raise ``PingError``.

    Called before every subprocess so user input can never reach the shell.
    """
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError as exc:
        raise PingError(f"Invalid IPv4 address: {value!r}") from exc


def build_ping_command(ip: str, count: int, timeout_s: float,
                       system: Optional[str] = None) -> List[str]:
    """Build the ping command line for the given operating system."""
    system = system or platform.system()
    if system == "Windows":                       # -n count, -w milliseconds
        return ["ping", "-n", str(count), "-w", str(int(timeout_s * 1000)), ip]
    if system == "Darwin":                        # -c count, -W milliseconds
        return ["ping", "-c", str(count), "-W", str(int(timeout_s * 1000)), ip]
    # Linux: -c count, -W whole seconds
    return ["ping", "-c", str(count), "-W", str(max(1, math.ceil(timeout_s))), ip]


def parse_ping_output(text: str) -> List[float]:
    """Extract the round-trip time (ms) of every reply in ``text``.

    ``time<1ms`` (Windows) is recorded as 1 ms.
    """
    times: List[float] = []
    for line in text.splitlines():
        if not _TTL_RE.search(line):
            continue
        match = _RTT_RE.search(line)
        if match:
            times.append(float(match.group(1).replace(",", ".")))
    return times


def ping_host(ip: str, count: int = config.PING_COUNT,
              timeout_s: float = config.PING_TIMEOUT_S,
              hostname: str = "Unknown") -> PingResult:
    """Send ``count`` echo requests to ``ip`` and return the raw result."""
    ip = validate_ipv4(ip)
    if not isinstance(count, int) or not 1 <= count <= 100:
        raise PingError("Ping count must be an integer between 1 and 100.")

    cmd = build_ping_command(ip, count, timeout_s)
    # Whole-command guard: every request may wait for its own timeout + 1 s gap.
    guard = count * (timeout_s + 1) + 5
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=guard)
        output = proc.stdout
    except FileNotFoundError as exc:
        raise PingError("The 'ping' utility was not found on this system.") from exc
    except subprocess.TimeoutExpired as exc:
        log.warning("ping to %s exceeded %.0fs guard; using partial output", ip, guard)
        partial = exc.stdout or ""
        output = partial.decode(errors="replace") if isinstance(partial, bytes) else partial
    except OSError as exc:
        raise PingError(f"Could not run ping: {exc}") from exc

    rtts = parse_ping_output(output)[:count]      # ignore duplicate (DUP!) replies
    result = PingResult(ip=ip, hostname=hostname, sent=count,
                        received=len(rtts), rtts_ms=rtts)
    log.debug("ping %s: %d/%d replies", ip, result.received, result.sent)
    return result
