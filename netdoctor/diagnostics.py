"""Layer-by-layer troubleshooting wizard (report, "Layer-by-layer diagnosis").

Five checks run in order and the procedure STOPS at the first failure:
  1 network adapter has a usable IP configuration
  2 default gateway answers ping
  3 an internet IP address answers ping
  4 a domain name resolves through DNS
  5 a TCP connection to an internet host succeeds

The result narrows down *possible* causes; it does not prove that one OSI
layer is solely responsible.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import config
from .discovery import DiscoveryError, get_default_gateway, get_local_ip
from .pinger import PingError, ping_host

log = logging.getLogger(__name__)
CheckFn = Callable[[Dict], Tuple[bool, str]]


@dataclass
class Check:
    stage: int
    name: str
    layer: str          # conceptual mapping from Table 3 (informational)
    func: CheckFn
    hint: str           # possible cause shown when this check fails


@dataclass
class CheckResult:
    stage: int
    name: str
    layer: str
    status: str         # "Passed" | "Failed" | "Skipped"
    detail: str = ""
    hint: str = ""


@dataclass
class DiagnosisResult:
    results: List[CheckResult] = field(default_factory=list)

    @property
    def failed(self) -> Optional[CheckResult]:
        return next((r for r in self.results if r.status == "Failed"), None)

    @property
    def passed(self) -> bool:
        return self.failed is None

    @property
    def summary(self) -> str:
        f = self.failed
        if f is None:
            return "All configured checks passed."
        return (f"Stage {f.stage} failed: {f.name}. {f.hint} "
                "(Possible cause only; later stages were not run.)")


# ------------------------------------------------------------------ checks
def check_ip_configuration(ctx: Dict) -> Tuple[bool, str]:
    try:
        ip = get_local_ip()
    except DiscoveryError as exc:
        return False, str(exc)
    ctx["local_ip"] = ip
    if ipaddress.IPv4Address(ip).is_link_local:
        return False, f"{ip} is a self-assigned (169.254.x.x) address; no DHCP lease."
    return True, f"Local IP address {ip}"


def _ping_check(ip: str, label: str) -> Tuple[bool, str]:
    try:
        r = ping_host(ip, count=config.DIAG_PING_COUNT)
    except PingError as exc:
        return False, str(exc)
    if r.received == 0:
        return False, f"{label} {ip}: no reply ({r.sent} requests sent)."
    return True, f"{label} {ip}: {r.received}/{r.sent} replies, avg {r.avg_ms} ms"


def check_gateway(ctx: Dict) -> Tuple[bool, str]:
    gateway = get_default_gateway()
    if not gateway:
        return False, "No default gateway is configured."
    ctx["gateway"] = gateway
    return _ping_check(gateway, "Gateway")


def check_internet_ip(ctx: Dict) -> Tuple[bool, str]:
    return _ping_check(config.DIAG_INTERNET_IP, "Internet host")


def _resolve(name: str, timeout_s: float) -> str:
    """IPv4 address for ``name``; a daemon thread enforces the timeout because
    ``getaddrinfo`` has none of its own."""
    box: Dict = {}

    def work():
        try:
            box["ip"] = socket.getaddrinfo(name, None, socket.AF_INET)[0][4][0]
        except OSError as exc:
            box["err"] = exc

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        raise TimeoutError("DNS lookup timed out")
    if "err" in box:
        raise box["err"]
    return box["ip"]


def check_dns(ctx: Dict) -> Tuple[bool, str]:
    try:
        ip = _resolve(config.DIAG_DNS_NAME, config.DIAG_DNS_TIMEOUT_S)
    except OSError as exc:
        return False, f"Could not resolve {config.DIAG_DNS_NAME}: {exc}"
    ctx["resolved_ip"] = ip
    return True, f"{config.DIAG_DNS_NAME} resolved to {ip}"


def check_tcp(ctx: Dict) -> Tuple[bool, str]:
    # Use the address resolved in stage 4 so this stage tests TCP only.
    host = ctx.get("resolved_ip") or config.DIAG_INTERNET_IP
    try:
        with socket.create_connection((host, config.DIAG_TCP_PORT),
                                      timeout=config.DIAG_TCP_TIMEOUT_S):
            return True, f"TCP connection to {host}:{config.DIAG_TCP_PORT} accepted"
    except OSError as exc:
        return False, f"TCP connection to {host}:{config.DIAG_TCP_PORT} failed: {exc}"


DEFAULT_CHECKS: List[Check] = [
    Check(1, "Network adapter / IP configuration", "Network (3)", check_ip_configuration,
          "The adapter may be disconnected or may not have received an IP address "
          "(check the cable, Wi-Fi connection and DHCP)."),
    Check(2, "Default gateway reachable (ping)", "Network (3)", check_gateway,
          "The router may be off, or the local link to it is down or unreliable."),
    Check(3, "Internet IP reachable (ping)", "Network (3)", check_internet_ip,
          "The local network works but the internet connection or ISP route may be "
          "down, or ICMP to that host may be blocked."),
    Check(4, "DNS name resolution", "Application (7)", check_dns,
          "Internet access by IP works, so the DNS server configuration or service "
          "may be at fault."),
    Check(5, "TCP connection to an internet host", "Transport (4)", check_tcp,
          "Name resolution works, but TCP connections may be blocked by a firewall "
          "or the remote service may be unavailable."),
]


def run_diagnosis(checks: Optional[List[Check]] = None,
                  progress: Optional[Callable[[CheckResult], None]] = None
                  ) -> DiagnosisResult:
    """Run checks in order; stop at the first failure (remaining = Skipped)."""
    checks = checks if checks is not None else DEFAULT_CHECKS
    out, ctx, stopped = DiagnosisResult(), {}, False
    for chk in checks:
        if stopped:
            res = CheckResult(chk.stage, chk.name, chk.layer, "Skipped")
        else:
            try:
                ok, detail = chk.func(ctx)
            except Exception as exc:                      # a check must never crash the wizard
                log.exception("diagnostic stage %d raised", chk.stage)
                ok, detail = False, f"Unexpected error: {exc}"
            res = CheckResult(chk.stage, chk.name, chk.layer,
                              "Passed" if ok else "Failed", detail,
                              "" if ok else chk.hint)
            stopped = not ok
        out.results.append(res)
        if progress:
            progress(res)
    return out
