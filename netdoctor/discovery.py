"""Network discovery: local IP, network range, gateway, ping sweep, ARP table,
hostnames and vendors (report, "Network discovery").
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from . import config
from .oui import lookup_vendor
from .pinger import ping_host

log = logging.getLogger(__name__)
ProgressFn = Optional[Callable[[int, int], None]]

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_MAC_RE = re.compile(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b")


class DiscoveryError(Exception):
    """Local network information could not be determined / invalid range."""


@dataclass
class Device:
    """A host found on the local network."""

    ip: str
    hostname: str = "Unknown"
    mac: Optional[str] = None
    vendor: str = "Unknown"
    via: str = "ICMP"          # "ICMP", "ARP" or "ICMP+ARP"

    @property
    def status(self) -> str:
        """Online = answered ping. ARP-only hosts are in the ARP cache but did
        not answer ping (the report: ICMP may be blocked), so availability is
        evidence-based, not confirmed."""
        return "Online" if "ICMP" in self.via else "ARP only"


# --------------------------------------------------------------- local info
def get_local_ip() -> str:
    """IP address the OS would use for an outbound route.

    A UDP ``connect`` sends no data; it only makes the OS choose the interface.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1.0)
        sock.connect(("10.255.255.255", 1))
        ip = sock.getsockname()[0]
    except OSError as exc:
        raise DiscoveryError("No network connection: local IP address not found.") from exc
    finally:
        sock.close()
    if ip.startswith("127."):
        raise DiscoveryError("Only a loopback address was found; connect to a network.")
    return ip


def get_network(ip: str, prefix: int = config.DEFAULT_PREFIX) -> ipaddress.IPv4Network:
    """Subnet containing ``ip`` (/24 by default) after validating the size."""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{int(prefix)}", strict=False)
    except ValueError as exc:
        raise DiscoveryError(f"Invalid address or prefix: {ip}/{prefix}") from exc
    return _check_size(network)


def parse_network(text: str) -> ipaddress.IPv4Network:
    """Validate a user-supplied CIDR range."""
    try:
        network = ipaddress.IPv4Network(text.strip(), strict=False)
    except ValueError as exc:
        raise DiscoveryError(f"Invalid network range: {text!r}") from exc
    return _check_size(network)


def _check_size(network: ipaddress.IPv4Network) -> ipaddress.IPv4Network:
    hosts = max(network.num_addresses - 2, 0)
    if hosts == 0:
        raise DiscoveryError(f"{network} has no usable host addresses.")
    if hosts > config.MAX_HOSTS:
        raise DiscoveryError(
            f"{network} has {hosts} hosts; discovery is limited to "
            f"{config.MAX_HOSTS} (use /22 or smaller).")
    return network


def parse_gateway(text: str) -> Optional[str]:
    """Default gateway from ``ip route`` / ``route -n`` / ``route -n get`` /
    ``route print`` output, or ``None``."""
    patterns = (
        r"default via (\d+\.\d+\.\d+\.\d+)",                     # ip route
        r"^0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+0\.0\.0\.0",      # route -n (Linux)
        r"gateway:\s*(\d+\.\d+\.\d+\.\d+)",                      # route -n get default (macOS)
        r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)",   # route print (Windows)
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            return match.group(1)
    return None


def _run(cmd: List[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("command %s failed: %s", cmd[0], exc)
        return ""


def get_default_gateway() -> Optional[str]:
    """Default gateway address using the OS ``route`` tooling, or ``None``."""
    system = platform.system()
    if system == "Windows":
        commands = [["route", "print", "-4", "0.0.0.0"]]
    elif system == "Darwin":
        commands = [["route", "-n", "get", "default"]]
    else:
        commands = [["ip", "route", "show", "default"], ["route", "-n"]]
    for cmd in commands:
        gateway = parse_gateway(_run(cmd))
        if gateway:
            return gateway
    log.warning("default gateway could not be determined")
    return None


# ---------------------------------------------------------------- ARP table
def normalize_mac(mac: str) -> str:
    """aa-bb-cc-dd-ee-ff / A:B:C:D:E:F -> aa:bb:cc:dd:ee:ff"""
    return ":".join(p.zfill(2) for p in re.split(r"[:-]", mac.strip().lower()))


def parse_arp_output(text: str) -> Dict[str, str]:
    """Parse ``arp -a`` (Windows/Linux/macOS) or ``ip neigh`` output.

    Incomplete, broadcast and multicast entries are discarded.
    """
    table: Dict[str, str] = {}
    for line in text.splitlines():
        ip_m, mac_m = _IP_RE.search(line), _MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        try:
            addr = ipaddress.IPv4Address(ip_m.group(1))
        except ValueError:
            continue
        mac = normalize_mac(mac_m.group(1))
        if addr.is_multicast or addr == ipaddress.IPv4Address("255.255.255.255"):
            continue
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        table[str(addr)] = mac
    return table


def read_arp_table() -> Dict[str, str]:
    """Read the OS ARP cache: ``{ip: mac}``."""
    table = parse_arp_output(_run(["arp", "-a"]))
    if not table and platform.system() not in ("Windows", "Darwin"):
        table = parse_arp_output(_run(["ip", "neigh"]))   # Linux without net-tools
    return table


# ------------------------------------------------------------------ hostnames
def resolve_hostname(ip: str) -> str:
    """Reverse-DNS lookup; ``"Unknown"`` if there is no name."""
    try:
        return socket.gethostbyaddr(ip)[0] or "Unknown"
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"


# ---------------------------------------------------------------------- sweep
def sweep_network(network: ipaddress.IPv4Network,
                  progress: ProgressFn = None) -> List[Device]:
    """Concurrent ping sweep combined with the ARP cache.

    Hosts that appear in the ARP cache are included even if they did not
    answer ping (ICMP may be blocked).
    """
    hosts = [str(h) for h in network.hosts()]
    counter = {"n": 0}

    def probe(ip: str) -> bool:
        alive = ping_host(ip, count=1, timeout_s=config.SWEEP_TIMEOUT_S).received > 0
        counter["n"] += 1
        if progress:
            progress(counter["n"], len(hosts))
        return alive

    with ThreadPoolExecutor(max_workers=config.SWEEP_WORKERS) as pool:
        replied = {ip for ip, ok in zip(hosts, pool.map(probe, hosts)) if ok}

    # Read ARP *after* the sweep: the sweep populates the cache.
    host_set = set(hosts)
    arp = {ip: mac for ip, mac in read_arp_table().items() if ip in host_set}

    found = sorted(replied | set(arp), key=ipaddress.IPv4Address)
    with ThreadPoolExecutor(max_workers=config.HOSTNAME_WORKERS) as pool:
        names = list(pool.map(resolve_hostname, found))

    devices = []
    for ip, name in zip(found, names):
        mac = arp.get(ip)
        via = "ICMP+ARP" if ip in replied and mac else ("ICMP" if ip in replied else "ARP")
        devices.append(Device(ip=ip, hostname=name, mac=mac,
                              vendor=lookup_vendor(mac), via=via))
    return devices


def discover(network: ipaddress.IPv4Network, progress: ProgressFn = None,
             max_attempts: int = config.MAX_SCAN_ATTEMPTS) -> List[Device]:
    """Sweep, and rescan while nothing is found (Figure 2: "Devices found? no:
    rescan"), bounded by ``max_attempts``."""
    devices: List[Device] = []
    for attempt in range(1, max_attempts + 1):
        devices = sweep_network(network, progress)
        if devices:
            break
        log.info("no devices found on %s (attempt %d/%d)", network, attempt, max_attempts)
    return devices
