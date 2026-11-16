"""Trusted-device baseline stored as JSON; finds unknown devices.

Devices are compared primarily by MAC address (IPs change with DHCP). The IP
address is the fallback only when a device's MAC is unavailable.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

from . import config
from .discovery import Device, normalize_mac

log = logging.getLogger(__name__)


class BaselineError(Exception):
    """Baseline file is unreadable or invalid."""


def save_baseline(devices: Iterable[Device], path: Path | str = config.BASELINE_PATH) -> int:
    """Write ``devices`` as the trusted baseline; returns how many were saved.

    The file is written atomically so a crash cannot leave a half-written
    baseline.
    """
    entries = [{"ip": d.ip, "mac": normalize_mac(d.mac) if d.mac else None,
                "hostname": d.hostname, "vendor": d.vendor} for d in devices]
    if not entries:
        raise BaselineError("There are no devices to save.")
    payload = {"version": 1, "saved_at": datetime.now().isoformat(timespec="seconds"),
               "devices": entries}
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, path)
    except OSError as exc:
        raise BaselineError(f"Could not write baseline {path}: {exc}") from exc
    log.info("baseline saved: %d device(s) -> %s", len(entries), path)
    return len(entries)


def load_baseline(path: Path | str = config.BASELINE_PATH) -> Optional[List[dict]]:
    """Trusted entries, or ``None`` when no baseline has been saved yet."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        devices = data["devices"]
        if not isinstance(devices, list):
            raise TypeError("'devices' must be a list")
        return devices
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise BaselineError(f"Baseline file {path} is invalid: {exc}") from exc


def find_unknown(devices: Iterable[Device], baseline: List[dict]) -> List[Device]:
    """Devices not present in ``baseline``."""
    trusted_macs = {normalize_mac(e["mac"]) for e in baseline if e.get("mac")}
    trusted_ips = {e.get("ip") for e in baseline}
    unknown = []
    for d in devices:
        trusted = (normalize_mac(d.mac) in trusted_macs) if d.mac else (d.ip in trusted_ips)
        if not trusted:
            unknown.append(d)
    return unknown
