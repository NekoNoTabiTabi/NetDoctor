"""Security recommendations: convert measurements into advisory messages.

Thresholds come from config (all [DOC]): 100 % loss = unreachable, >= 20 %
loss = weak connectivity, >= 100 ms average latency = high latency, open
FTP/Telnet = review. Messages are preliminary advice, not proof of compromise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from . import config
from .discovery import Device
from .stats import DeviceStats

WARNING, INFO = "Warning", "Info"


@dataclass
class Recommendation:
    severity: str      # "Warning" | "Info"
    category: str
    target: str        # IP address or "Network"
    message: str


def analyze(stats: Iterable[DeviceStats],
            open_ports: Optional[Dict[str, List[int]]] = None,
            unknown_devices: Optional[List[Device]] = None) -> List[Recommendation]:
    """Return recommendations, warnings first.

    ``unknown_devices`` is ``None`` when no trusted baseline exists (the
    check cannot run) and ``[]`` when a baseline exists and all is trusted.
    """
    recs: List[Recommendation] = []
    open_ports = open_ports or {}

    for s in stats:
        name = f"{s.hostname} ({s.ip})"
        if s.unreachable:
            recs.append(Recommendation(
                WARNING, "Unreachable host", s.ip,
                f"{name} did not reply to any ping request (100% packet loss). "
                "It may be powered off or disconnected, or it may block ICMP echo "
                "requests; check whether the device is expected on the network."))
        elif s.high_loss:
            recs.append(Recommendation(
                WARNING, "Weak connectivity", s.ip,
                f"{name} lost {s.loss_pct}% of ping requests (threshold "
                f"{config.WEAK_LOSS_PCT:.0f}%). Check cabling, Wi-Fi signal and "
                "possible interference."))
        if s.avg_ms is not None and s.avg_ms >= config.HIGH_LATENCY_MS:
            recs.append(Recommendation(
                WARNING, "High latency", s.ip,
                f"Average latency to {name} is {s.avg_ms} ms (threshold "
                f"{config.HIGH_LATENCY_MS:.0f} ms). Heavy traffic or a weak link "
                "may be the cause."))

    for ip, ports in open_ports.items():
        for port in ports:
            if port in config.FLAGGED_PORTS:
                svc = config.FLAGGED_PORTS[port]
                recs.append(Recommendation(
                    WARNING, "Potentially risky service", ip,
                    f"{ip} accepted a TCP connection on port {port} ({svc}). "
                    f"{svc} traditionally sends data, including credentials, "
                    "without encryption. Review whether it is needed; if so, "
                    "prefer an encrypted alternative (SFTP/SSH). An open port "
                    "does not by itself mean the device is compromised."))

    if unknown_devices is None:
        recs.append(Recommendation(
            INFO, "Trusted-device baseline", "Network",
            "No trusted-device baseline has been saved, so unknown devices "
            "cannot be identified. Save the baseline once you have confirmed "
            "that every listed device belongs on your network."))
    else:
        for d in unknown_devices:
            recs.append(Recommendation(
                WARNING, "Unknown device", d.ip,
                f"{d.hostname} ({d.ip}, MAC {d.mac or 'unavailable'}, "
                f"vendor {d.vendor}) is not in the trusted-device baseline. "
                "Confirm that you recognise it; if you do, add it to the baseline."))

    recs += [
        Recommendation(INFO, "Firewall", "Network",
                       "Keep the firewall enabled on the router and on each device; "
                       "allow only the services you need."),
        Recommendation(INFO, "Password", "Network",
                       "Use strong, unique passwords for the router, Wi-Fi and "
                       "devices, and change any default credentials."),
        Recommendation(INFO, "Updates", "Network",
                       "Install router firmware and operating-system updates "
                       "regularly."),
    ]
    recs.sort(key=lambda r: r.severity != WARNING)      # stable: warnings first
    return recs
