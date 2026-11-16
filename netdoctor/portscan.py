"""TCP port checks on common service ports (21, 22, 23, 80, 443, 3389).

A successful connection only means the endpoint accepted a connection at that
moment; it does not mean the service is secure. Use only on devices and
networks you are authorised to assess.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, Iterable, List, Optional

from . import config


def check_port(ip: str, port: int, timeout_s: float = config.PORT_TIMEOUT_S) -> bool:
    """True if a TCP connection to ``ip:port`` is accepted within the timeout."""
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def scan_ports(ip: str, ports: Iterable[int] = tuple(config.PORTS),
               timeout_s: float = config.PORT_TIMEOUT_S) -> List[int]:
    """Open ports (sorted) among ``ports`` on one host, checked concurrently."""
    ports = list(ports)
    with ThreadPoolExecutor(max_workers=min(len(ports), config.PORT_WORKERS) or 1) as pool:
        results = list(pool.map(lambda p: check_port(ip, p, timeout_s), ports))
    return sorted(p for p, ok in zip(ports, results) if ok)


def scan_devices(ips: Iterable[str],
                 progress: Optional[Callable[[int, int], None]] = None
                 ) -> Dict[str, List[int]]:
    """``{ip: [open ports]}`` for every ip."""
    ips = list(ips)
    out: Dict[str, List[int]] = {}
    for i, ip in enumerate(ips, 1):
        out[ip] = scan_ports(ip)
        if progress:
            progress(i, len(ips))
    return out


def port_label(port: int) -> str:
    return f"{port}/{config.PORTS.get(port, 'TCP')}"
