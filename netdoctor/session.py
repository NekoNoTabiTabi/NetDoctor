"""MonitoringSession: the Figure 2 workflow, shared by the GUI and console mode.

NOT listed in the report's Table 2. It exists so that both interfaces run the
same sequence (detect -> scan -> measure -> ports/baseline -> health ->
recommendations -> report) without duplicating it. See GAP_ANALYSIS (G-17).
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import config, security
from .baseline import BaselineError, find_unknown, load_baseline, save_baseline
from .diagnostics import DiagnosisResult, run_diagnosis
from .discovery import (Device, discover, get_default_gateway, get_local_ip,
                        get_network, parse_network)
from .health import HealthScore, compute_health
from .portscan import scan_devices
from .report import save_reports
from .stats import DeviceStats, measure_devices

log = logging.getLogger(__name__)
ProgressFn = Optional[Callable[[int, int], None]]


class MonitoringSession:
    def __init__(self, baseline_path: Path | str = config.BASELINE_PATH,
                 prefix: int = config.DEFAULT_PREFIX):
        self.baseline_path = Path(baseline_path)
        self.prefix = prefix
        self.local_ip = ""
        self.network = ""
        self.gateway: Optional[str] = None
        self.scanned_at = datetime.now()
        self.devices: List[Device] = []
        self.stats: List[DeviceStats] = []
        self.open_ports: Dict[str, List[int]] = {}
        self.unknown_devices: Optional[List[Device]] = None   # None = no baseline
        self.health: Optional[HealthScore] = None
        self.diagnosis: Optional[DiagnosisResult] = None
        self.recommendations: List[security.Recommendation] = []
        self.baseline_error: Optional[str] = None

    # ------------------------------------------------------- 1. local info
    def detect_network(self, network_text: Optional[str] = None) -> Tuple[str, str, Optional[str]]:
        """Local IP, network range and gateway. ``network_text`` overrides the range."""
        self.local_ip = get_local_ip()
        net = parse_network(network_text) if network_text else get_network(self.local_ip, self.prefix)
        self.network = str(net)
        self.gateway = get_default_gateway()
        log.info("local %s, network %s, gateway %s", self.local_ip, self.network, self.gateway)
        return self.local_ip, self.network, self.gateway

    # ------------------------------------------------------------ 2. scan
    def scan(self, progress: ProgressFn = None) -> List[Device]:
        if not self.network:
            self.detect_network()
        self.scanned_at = datetime.now()
        self.devices = discover(parse_network(self.network), progress)
        self.stats, self.open_ports, self.health = [], {}, None   # old results are stale
        self.refresh_analysis()
        return self.devices

    # -------------------------------------------------- 3. measure selected
    def measure(self, selected: Sequence[str], progress: ProgressFn = None) -> List[DeviceStats]:
        """Ping 10x, check TCP ports, compare with baseline, score, advise."""
        by_ip = {d.ip: d for d in self.devices}
        chosen = [by_ip[ip] for ip in selected if ip in by_ip]
        if not chosen:
            raise ValueError("Select at least one device to test.")
        self.stats = measure_devices(chosen, progress=progress)
        self.open_ports = scan_devices(d.ip for d in chosen)
        self.refresh_analysis()
        return self.stats

    def refresh_analysis(self) -> None:
        """Recompute baseline comparison, health score and recommendations."""
        self.unknown_devices, self.baseline_error = None, None
        try:
            baseline = load_baseline(self.baseline_path)
            if baseline is not None:
                self.unknown_devices = find_unknown(self.devices, baseline)
        except BaselineError as exc:
            log.error("%s", exc)
            self.baseline_error = str(exc)
        self.health = compute_health(self.stats)
        self.recommendations = security.analyze(self.stats, self.open_ports,
                                                self.unknown_devices)

    # ------------------------------------------------------- 4. diagnosis
    def diagnose(self, progress=None) -> DiagnosisResult:
        self.diagnosis = run_diagnosis(progress=progress)
        return self.diagnosis

    # --------------------------------------------------------- 5. baseline
    def save_baseline(self, ips: Optional[Sequence[str]] = None) -> int:
        """Save ``ips`` (default: all discovered devices) as the trusted baseline."""
        devices = [d for d in self.devices if ips is None or d.ip in ips]
        count = save_baseline(devices, self.baseline_path)
        self.refresh_analysis()
        return count

    # ----------------------------------------------------------- 6. report
    def generate_report(self, directory: Path | str = config.REPORT_DIR) -> Tuple[Path, Path]:
        return save_reports(self, directory)
