"""Every threshold and default in one place.

Each value is tagged with its source:
  [DOC]  stated in the Final Technical Report - do not change without
         updating the report.
  [IMPL] not specified by the report; an implementation choice that is
         listed under "Open decisions" in docs/GAP_ANALYSIS.md.
"""

from pathlib import Path

# --- Paths ---------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"
BASELINE_PATH = DATA_DIR / "baseline.json"        # [DOC] JSON baseline file

# --- Discovery (Chapter 3, "Network discovery") ----------------------------
DEFAULT_PREFIX = 24          # [DOC] /24 unless configured otherwise
MAX_HOSTS = 1022             # [DOC] maximum host addresses per discovery
MAX_SCAN_ATTEMPTS = 3        # [IMPL] bound for the flow chart's "no: rescan" loop
SWEEP_TIMEOUT_S = 1.0        # [IMPL]
SWEEP_WORKERS = 64           # [IMPL]
HOSTNAME_WORKERS = 32        # [IMPL]

# --- Connectivity test -----------------------------------------------------
PING_COUNT = 10              # [DOC] "sends ten ping requests" (Figure 2)
PING_TIMEOUT_S = 2.0         # [IMPL] per-request timeout
MEASURE_WORKERS = 8          # [IMPL] devices measured in parallel

# --- TCP port checks -------------------------------------------------------
PORTS = {                    # [DOC] 21, 22, 23, 80, 443, 3389
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3389: "RDP",
}
PORT_TIMEOUT_S = 0.5         # [DOC] "short timeout" - value is [IMPL]
PORT_WORKERS = 16            # [IMPL]
FLAGGED_PORTS = {            # [DOC] "Open FTP or Telnet ports are flagged"
    21: "FTP", 23: "Telnet",
}

# --- Security thresholds (Chapter 3, "Security recommendations") ----------
UNREACHABLE_LOSS_PCT = 100.0   # [DOC] 100 % loss  -> unreachable
WEAK_LOSS_PCT = 20.0           # [DOC] >= 20 %     -> weak connectivity
HIGH_LATENCY_MS = 100.0        # [DOC] >= 100 ms   -> high latency

# --- Network health score (Chapter 3, "Network health score") ------------
REACHABILITY_POINTS = 40       # [DOC]
LOSS_POINTS = 30               # [DOC]
LATENCY_POINTS = 30            # [DOC]
LOSS_ZERO_AT_PCT = 30.0        # [DOC] loss component reaches 0 at 30 % loss
LATENCY_FULL_AT_MS = 20.0      # [DOC] full latency points at <= 20 ms
LATENCY_ZERO_AT_MS = 200.0     # [DOC] zero latency points at 200 ms
RATING_BANDS = (               # [DOC] Excellent 90-100, Good 75-89, Fair 60-74
    (90, "Excellent"), (75, "Good"), (60, "Fair"), (0, "Poor"),
)

# --- Layer-by-layer diagnosis (targets are NOT specified by the report) ---
DIAG_PING_COUNT = 4            # [IMPL]
DIAG_INTERNET_IP = "8.8.8.8"   # [IMPL] "a selected internet IP address"
DIAG_DNS_NAME = "example.com"  # [IMPL] "a domain name"
DIAG_TCP_PORT = 443            # [IMPL] "a TCP connection to an internet host"
DIAG_DNS_TIMEOUT_S = 3.0       # [IMPL]
DIAG_TCP_TIMEOUT_S = 3.0       # [IMPL]

# --- GUI -------------------------------------------------------------------
APP_TITLE = "NetDoctor - Network Monitoring and Performance Analysis"
