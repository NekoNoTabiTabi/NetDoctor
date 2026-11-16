"""Report generator: text and HTML (report, "Trusted-device baseline and reporting").

Contents: date/time, local IP, network range, detected devices, ping results,
performance summary, network health score, diagnostic outcome, recommendations.

``session`` is duck-typed (see ``session.MonitoringSession``); this module does
not import it, which keeps reporting independent of the workflow code.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import List, Sequence, Tuple

from . import config
from .portscan import port_label
from .stats import TABLE_HEADERS

DEVICE_HEADERS = ("Hostname", "IP Address", "MAC Address", "Vendor", "Detected via",
                  "Status", "Trust")      # same columns as the GUI device list


class ReportError(Exception):
    """Report could not be created or written."""


def text_table(headers: Sequence[str], rows: Sequence[Sequence]) -> str:
    """Fixed-width text table (also used by console mode)."""
    cells = [[str(c) for c in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in cells)) if cells else len(h)
              for i, h in enumerate(headers)]
    line = lambda vals: "  ".join(v.ljust(w) for v, w in zip(vals, widths)).rstrip()
    return "\n".join([line(headers), "  ".join("-" * w for w in widths)]
                     + [line(r) for r in cells])


def _trust(session, device) -> str:
    if session.unknown_devices is None:
        return "No baseline"
    return "UNKNOWN" if device in session.unknown_devices else "Trusted"


def _sections(session) -> List[Tuple[str, List[Tuple[str, list]], List[str]]]:
    """Report content as (title, [(headers, rows)...], [paragraph lines])."""
    # Each section: title, optional table (headers, rows), free-text lines.
    secs = []
    secs.append(("Scan Information", None, [
        f"Date and time of scan : {session.scanned_at:%Y-%m-%d %H:%M:%S}",
        f"Local IP address      : {session.local_ip}",
        f"Network range         : {session.network}",
        f"Default gateway       : {session.gateway or 'Not detected'}",
        f"Devices detected      : {len(session.devices)}"]))

    measured = {s.ip: s.status for s in session.stats}      # tested -> Online/Unreachable
    secs.append(("Detected Devices", (DEVICE_HEADERS, [
        (d.hostname, d.ip, d.mac or "-", d.vendor, d.via,
         measured.get(d.ip, d.status), _trust(session, d))
        for d in session.devices]), []))

    if session.stats:
        secs.append(("Connectivity Test Results", (TABLE_HEADERS,
                     [s.as_row() for s in session.stats]), []))
        ports = [f"{ip}: {', '.join(port_label(p) for p in plist) or 'no checked port open'}"
                 for ip, plist in session.open_ports.items()]
        secs.append(("TCP Port Checks (21, 22, 23, 80, 443, 3389)", None, ports or ["Not run."]))
    else:
        secs.append(("Connectivity Test Results", None, ["No devices were tested."]))

    h = session.health
    if h:
        secs.append(("Network Performance Summary", None, [
            f"Devices tested        : {h.tested} ({h.responding} responding, "
            f"{h.tested - h.responding} unreachable)",
            f"Average packet loss   : {h.avg_loss_pct}%",
            "Average latency       : "
            + ("N/A" if h.avg_latency_ms is None else f"{h.avg_latency_ms} ms")]))
        secs.append(("Network Health Score", None, [
            f"Score: {h.score} / 100  ({h.rating})",
            f"Reachability {h.reachability_pts}/{config.REACHABILITY_POINTS}  |  "
            f"Packet loss {h.loss_pts}/{config.LOSS_POINTS}  |  "
            f"Latency {h.latency_pts}/{config.LATENCY_POINTS}",
            "The score is a project-defined indicator, not an industry-standard rating."]))
    else:
        secs.append(("Network Performance Summary", None, ["No measurements available."]))
        secs.append(("Network Health Score", None, ["Not calculated."]))

    d = session.diagnosis
    if d:
        rows = [(r.stage, r.name, r.status, r.detail) for r in d.results]
        secs.append(("Diagnostic Outcome", (("Stage", "Check", "Result", "Detail"), rows),
                     [d.summary]))
    else:
        secs.append(("Diagnostic Outcome", None, ["Layer diagnosis was not run."]))

    secs.append(("Security Recommendations", (("Severity", "Category", "Target", "Recommendation"),
                 [(r.severity, r.category, r.target, r.message)
                  for r in session.recommendations]), [
        "These are preliminary recommendations, not confirmation that any device "
        "has been compromised."]))
    return secs


def build_text(session) -> str:
    out = ["NETDOCTOR - NETWORK MONITORING REPORT", "=" * 38, ""]
    for i, (title, table, lines) in enumerate(_sections(session), 1):
        out += [f"{i}. {title}", "-" * (len(title) + 3)]
        if table:
            out.append(text_table(*table))
        out += lines + [""]
    return "\n".join(out)


_CSS = """
body{font-family:Segoe UI,Arial,sans-serif;margin:2rem auto;max-width:1000px;color:#1b2733}
h1{color:#1f4e79}h2{color:#1f4e79;border-bottom:2px solid #d5dee8;padding-bottom:.2rem;margin-top:2rem}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th{background:#1f4e79;color:#fff;text-align:left}th,td{padding:.35rem .5rem;border:1px solid #c5d0dc}
tr:nth-child(even) td{background:#f2f6fa}
tr.bad td{background:#fbe3e1;color:#8c1c13}tr.warn td{background:#fdf0d5;color:#7a4b00}
.score{font-size:2rem;font-weight:700}.note{color:#5b6b7b;font-size:.85rem}
@media print{body{margin:0}}
"""


def _row_class(session, table_title: str, row) -> str:
    """Highlight rows the way the GUI does (unreachable / high loss / unknown)."""
    text = [str(c) for c in row]
    if table_title.startswith("Connectivity"):
        if "Unreachable" in text:
            return "bad"
        try:
            if float(text[5]) >= config.WEAK_LOSS_PCT:
                return "warn"
        except (ValueError, IndexError):
            pass
    if table_title.startswith("Detected") and "UNKNOWN" in text:
        return "warn"
    if table_title.startswith("Security") and text[0] == "Warning":
        return "warn"
    return ""


def build_html(session) -> str:
    esc = html.escape
    parts = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
             "<title>NetDoctor Report</title><style>", _CSS, "</style></head><body>",
             "<h1>NetDoctor - Network Monitoring Report</h1>"]
    for title, table, lines in _sections(session):
        parts.append(f"<h2>{esc(title)}</h2>")
        if title == "Network Health Score" and session.health:
            parts.append(f"<p class='score'>{session.health.score} / 100 "
                         f"({esc(session.health.rating)})</p>")
        if table:
            headers, rows = table
            parts.append("<table><tr>" + "".join(f"<th>{esc(str(h))}</th>" for h in headers)
                         + "</tr>")
            for row in rows:
                cls = _row_class(session, title, row)
                parts.append(f"<tr class='{cls}'>" + "".join(
                    f"<td>{esc(str(c))}</td>" for c in row) + "</tr>")
            parts.append("</table>")
        for line in lines:
            parts.append(f"<p class='note'>{esc(line)}</p>" if "preliminary" in line
                         or "project-defined" in line else f"<p>{esc(line)}</p>")
    parts.append("</body></html>")
    return "".join(parts)


def save_reports(session, directory: Path | str = config.REPORT_DIR) -> Tuple[Path, Path]:
    """Write ``<stamp>.txt`` and ``<stamp>.html``; returns both paths."""
    if not session.devices:
        raise ReportError("There is no scan data to report. Scan the network first.")
    directory = Path(directory)
    stamp = f"netdoctor_report_{session.scanned_at:%Y%m%d_%H%M%S}"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        txt, htm = directory / f"{stamp}.txt", directory / f"{stamp}.html"
        txt.write_text(build_text(session), encoding="utf-8")
        htm.write_text(build_html(session), encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Could not write report to {directory}: {exc}") from exc
    return txt, htm
