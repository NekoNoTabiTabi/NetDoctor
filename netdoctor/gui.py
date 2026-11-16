"""Tkinter interface (report, "Graphical interface").

Shows: local IP, network range, default gateway, discovered-device list,
performance statistics, diagnostic output, security recommendations and the
network health score. Devices can be multi-selected for testing.

Threading: scanning/measuring run in worker threads. Workers never touch
widgets; they put messages on ``self.queue`` and the main thread drains it in
``_poll_queue``. Unreachable devices and devices with high packet loss are
highlighted.
"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Optional

from . import config
from .baseline import BaselineError
from .diagnostics import CheckResult
from .discovery import DiscoveryError
from .pinger import PingError
from .report import ReportError
from .session import MonitoringSession
from .stats import TABLE_HEADERS

log = logging.getLogger(__name__)

BAD = ("#fbe3e1", "#8c1c13")       # unreachable
WARN = ("#fdf0d5", "#7a4b00")      # high packet loss / unknown device / warning
RATING_COLORS = {"Excellent": "#1e7e34", "Good": "#2d8a5f", "Fair": "#b36b00", "Poor": "#b3261e"}
EXPECTED_ERRORS = (DiscoveryError, PingError, BaselineError, ReportError, ValueError)

AUTH_NOTICE = ("NetDoctor sends ping requests and TCP connection attempts.\n\n"
               "Use it only on networks and devices you own or are authorised to assess.\n\n"
               "Continue?")


def make_tree(parent, columns, widths, selectmode="browse", height=12) -> ttk.Treeview:
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True)
    tree = ttk.Treeview(frame, columns=columns, show="headings",
                        selectmode=selectmode, height=height)
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=widths.get(col, 120), anchor="w")
    scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scroll.set)
    tree.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")
    tree.tag_configure("bad", background=BAD[0], foreground=BAD[1])
    tree.tag_configure("warn", background=WARN[0], foreground=WARN[1])
    return tree


def fill(tree: ttk.Treeview, rows) -> None:
    """Replace the content of ``tree``; each row is ``(values, tag)``."""
    tree.delete(*tree.get_children())
    for values, tag in rows:
        tree.insert("", "end", values=values, tags=(tag,) if tag else ())


class NetDoctorApp(tk.Tk):
    DEVICE_COLS = ("Hostname", "IP Address", "MAC Address", "Vendor", "Detected via",
                   "Status", "Trust")

    def __init__(self, session: Optional[MonitoringSession] = None):
        super().__init__()
        self.title(config.APP_TITLE)
        self.geometry("1180x760")
        self.minsize(960, 620)
        self.session = session or MonitoringSession()
        self.queue: "queue.Queue" = queue.Queue()
        self.busy = False
        self.acknowledged = False

        ttk.Style(self).theme_use("clam")
        self._build_info_bar()
        self._build_toolbar()
        self._build_alert_bar()
        self._build_tabs()
        self._build_status_bar()
        self.after(100, self._poll_queue)
        self.after(300, self.detect_network)

    # ---------------------------------------------------------------- layout
    def _build_info_bar(self):
        bar = ttk.Frame(self, padding=(12, 10))
        bar.pack(fill="x")
        self.lbl_ip = ttk.Label(bar, text="Local IP: ...", font=("TkDefaultFont", 11, "bold"))
        self.lbl_net = ttk.Label(bar, text="Network range: ...", font=("TkDefaultFont", 11, "bold"))
        self.lbl_gw = ttk.Label(bar, text="Default gateway: ...", font=("TkDefaultFont", 11, "bold"))
        for lbl in (self.lbl_ip, self.lbl_net, self.lbl_gw):
            lbl.pack(side="left", padx=(0, 24))
        self.lbl_health = ttk.Label(bar, text="Network Health Score: not measured",
                                    font=("TkDefaultFont", 12, "bold"))
        self.lbl_health.pack(side="right")

    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=(12, 0, 12, 6))
        bar.pack(fill="x")
        ttk.Label(bar, text="Network range:").pack(side="left")
        self.range_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.range_var, width=18).pack(side="left", padx=(4, 12))
        self.buttons = []
        for text, cmd in (("Scan Network", self.scan),
                          ("Test Selected Devices", self.test_selected),
                          ("Run Layer Diagnosis", self.run_diagnosis),
                          ("Save Trusted Baseline", self.save_baseline),
                          ("Generate Report", self.generate_report)):
            btn = ttk.Button(bar, text=text, command=cmd)
            btn.pack(side="left", padx=3)
            self.buttons.append(btn)

    def _build_alert_bar(self):
        self.alert = tk.Label(self, text="", anchor="w", padx=12, pady=4,
                              font=("TkDefaultFont", 10, "bold"))
        self.alert.pack(fill="x", padx=12)

    def _build_tabs(self):
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=6)
        names = ("Network Devices", "Network Statistics", "Layer Diagnosis",
                 "Security Recommendations")
        frames = {n: ttk.Frame(self.tabs, padding=6) for n in names}
        for n, f in frames.items():
            self.tabs.add(f, text=n)

        # Network Devices (multi-select: "Users can select multiple devices")
        self.lbl_devices = ttk.Label(frames[names[0]], text="0 devices detected")
        self.lbl_devices.pack(anchor="w", pady=(0, 4))
        self.tree_devices = make_tree(
            frames[names[0]], self.DEVICE_COLS,
            {"Hostname": 260, "IP Address": 120, "MAC Address": 140, "Vendor": 170,
             "Detected via": 90, "Status": 90, "Trust": 90}, selectmode="extended")

        # Network Statistics
        self.lbl_summary = ttk.Label(frames[names[1]], text="No devices tested yet.",
                                     justify="left")
        self.lbl_summary.pack(anchor="w", pady=(0, 4))
        self.tree_stats = make_tree(
            frames[names[1]], TABLE_HEADERS,
            {"Hostname": 220, "IP Address": 120, "Average Latency (ms)": 170,
             "Maximum Latency (ms)": 170, "Minimum Latency (ms)": 170,
             "Packet Loss (%)": 120, "Status": 90})

        # Layer Diagnosis
        self.lbl_diag = ttk.Label(frames[names[2]], text="Diagnosis not run.",
                                  wraplength=1050, justify="left")
        self.lbl_diag.pack(anchor="w", pady=(0, 4))
        self.tree_diag = make_tree(
            frames[names[2]], ("Stage", "Check", "Layer", "Result", "Detail"),
            {"Stage": 50, "Check": 260, "Layer": 110, "Result": 80, "Detail": 560})

        # Security Recommendations
        self.tree_recs = make_tree(
            frames[names[3]], ("Severity", "Category", "Target", "Recommendation"),
            {"Severity": 80, "Category": 170, "Target": 110, "Recommendation": 760})
        # Long messages do not fit a table cell: show the selected one in full.
        self.lbl_rec_detail = ttk.Label(frames[names[3]], text="Select a recommendation to read it in full.",
                                        wraplength=1050, justify="left", padding=(2, 8))
        self.lbl_rec_detail.pack(fill="x")
        self.tree_recs.bind("<<TreeviewSelect>>", self._show_recommendation)

    def _build_status_bar(self):
        bar = ttk.Frame(self, padding=(12, 4))
        bar.pack(fill="x", side="bottom")
        self.status = ttk.Label(bar, text="Ready")
        self.status.pack(side="left")
        self.progress = ttk.Progressbar(bar, length=240, mode="determinate")
        self.progress.pack(side="right")

    # ------------------------------------------------- worker thread plumbing
    def _run_async(self, work: Callable[[Callable], object], on_done: Callable,
                   busy_text: str) -> None:
        """Run ``work(progress)`` in a thread; ``on_done(result)`` runs on the GUI thread."""
        if self.busy:
            messagebox.showinfo("Please wait", "Another operation is still running.")
            return
        self._set_busy(True, busy_text)

        def progress(done, total):
            self.queue.put(("progress", done, total))

        def target():
            try:
                self.queue.put(("done", on_done, work(progress), None))
            except Exception as exc:                          # reported on the GUI thread
                log.exception("background task failed")
                self.queue.put(("done", on_done, None, exc))

        threading.Thread(target=target, daemon=True).start()

    def _poll_queue(self):
        """Drain worker messages on the main thread (the only place widgets change)."""
        try:
            while True:
                msg = self.queue.get_nowait()
                if msg[0] == "progress":
                    _, done, total = msg
                    self.progress.configure(mode="determinate", maximum=max(total, 1), value=done)
                else:
                    _, on_done, result, error = msg
                    self._set_busy(False)
                    if error:
                        self._show_error(error)
                    else:
                        on_done(result)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _set_busy(self, busy: bool, text: Optional[str] = None):
        self.busy = busy
        for b in self.buttons:
            b.state(["disabled"] if busy else ["!disabled"])
        if busy:
            self.progress.configure(value=0)
        if text:
            self.status.configure(text=text)

    def _show_error(self, error: Exception):
        if isinstance(error, EXPECTED_ERRORS):
            self.status.configure(text=f"Error: {error}")
            messagebox.showerror("NetDoctor", str(error))
        else:
            self.status.configure(text="Unexpected error - see logs/netdoctor.log")
            messagebox.showerror("Unexpected error",
                                 f"{type(error).__name__}: {error}\n\nDetails were written to "
                                 "logs/netdoctor.log.")

    # ---------------------------------------------------------------- actions
    def detect_network(self):
        def done(info):
            ip, net, gw = info
            self.lbl_ip.configure(text=f"Local IP: {ip}")
            self.lbl_net.configure(text=f"Network range: {net}")
            self.lbl_gw.configure(text=f"Default gateway: {gw or 'not detected'}")
            self.range_var.set(net)
            self.status.configure(text="Ready. Click 'Scan Network' to find devices.")
        self._run_async(lambda p: self.session.detect_network(), done, "Detecting network...")

    def scan(self):
        if not self.acknowledged:
            if not messagebox.askokcancel("Authorised use only", AUTH_NOTICE):
                return
            self.acknowledged = True
        text = self.range_var.get().strip() or None

        def work(progress):
            self.session.detect_network(text)
            return self.session.scan(progress)

        def done(devices):
            self.lbl_net.configure(text=f"Network range: {self.session.network}")
            self.lbl_gw.configure(text=f"Default gateway: {self.session.gateway or 'not detected'}")
            self.refresh()
            msg = f"{len(devices)} device(s) detected."
            if not devices:
                msg = "No devices detected after rescanning. Check the network range."
            self.status.configure(text=msg)
        self._run_async(work, done, f"Scanning {text or 'local subnet'} (ping sweep + ARP table)...")

    def _selected_ips(self):
        return [self.tree_devices.item(i, "values")[1] for i in self.tree_devices.selection()]

    def test_selected(self):
        ips = self._selected_ips()
        if not ips:
            messagebox.showwarning("No device selected",
                                   "Select one or more devices on the Network Devices tab first "
                                   "(Ctrl/Shift-click for several).")
            return

        def done(_):
            self.refresh()
            self.tabs.select(1)
            self.status.configure(text=f"Tested {len(ips)} device(s).")
        self._run_async(lambda p: self.session.measure(ips, p), done,
                        f"Testing {len(ips)} device(s): {config.PING_COUNT} ping requests each "
                        "+ TCP port checks (this takes about 15 seconds)...")

    def run_diagnosis(self):
        self.tree_diag.delete(*self.tree_diag.get_children())

        def work(progress):
            return self.session.diagnose()

        def done(result):
            self.refresh()
            self.tabs.select(2)
            self.status.configure(text="Diagnosis finished.")
        self._run_async(work, done, "Running layer-by-layer diagnosis...")

    def save_baseline(self):
        ips = self._selected_ips()
        if not self.session.devices:
            return messagebox.showwarning("No devices", "Scan the network first.")
        if not ips:
            if not messagebox.askyesno(
                    "Save trusted baseline",
                    f"No device is selected.\n\nSave all {len(self.session.devices)} detected "
                    "devices as trusted?\nOnly do this if you recognise every one of them."):
                return
            ips = None
        try:
            count = self.session.save_baseline(ips)
        except EXPECTED_ERRORS as exc:
            return self._show_error(exc)
        self.refresh()
        self.status.configure(text=f"Trusted baseline saved ({count} device(s)).")

    def generate_report(self):
        try:
            txt, htm = self.session.generate_report()
        except EXPECTED_ERRORS as exc:
            return self._show_error(exc)
        self.status.configure(text=f"Report saved: {htm}")
        messagebox.showinfo("Report generated", f"Text: {txt}\nHTML: {htm}")

    def _show_recommendation(self, _event=None):
        sel = self.tree_recs.selection()
        if sel:
            sev, cat, target, msg = self.tree_recs.item(sel[0], "values")
            self.lbl_rec_detail.configure(text=f"[{sev}] {cat} - {target}\n{msg}")

    # --------------------------------------------------------------- rendering
    def refresh(self):
        s = self.session
        measured = {x.ip: x for x in s.stats}
        keep_selected = set(self._selected_ips())      # table is rebuilt below

        rows = []
        for d in s.devices:
            m = measured.get(d.ip)
            status = m.status if m else d.status
            trust = ("No baseline" if s.unknown_devices is None
                     else "UNKNOWN" if d in s.unknown_devices else "Trusted")
            tag = "bad" if status == "Unreachable" else \
                  "warn" if (trust == "UNKNOWN" or (m and m.high_loss)) else ""
            rows.append(((d.hostname, d.ip, d.mac or "-", d.vendor, d.via, status, trust), tag))
        fill(self.tree_devices, rows)
        self.tree_devices.selection_set([i for i in self.tree_devices.get_children()
                                         if self.tree_devices.item(i, "values")[1] in keep_selected])
        self.lbl_devices.configure(text=f"{len(s.devices)} devices detected")

        fill(self.tree_stats, [(x.as_row(), "bad" if x.unreachable else "warn" if x.high_loss else "")
                               for x in s.stats])

        h = s.health
        if h:
            self.lbl_health.configure(
                text=f"Network Health Score: {h.score} / 100 ({h.rating})",
                foreground=RATING_COLORS[h.rating])
            lat = "N/A" if h.avg_latency_ms is None else f"{h.avg_latency_ms} ms"
            self.lbl_summary.configure(text=(
                f"Reachability {h.reachability_pts}/{config.REACHABILITY_POINTS}   "
                f"Packet loss {h.loss_pts}/{config.LOSS_POINTS}   "
                f"Latency {h.latency_pts}/{config.LATENCY_POINTS}   |   "
                f"{h.responding}/{h.tested} devices responding   "
                f"Average packet loss {h.avg_loss_pct}%   Average latency {lat}"))
        else:
            self.lbl_health.configure(text="Network Health Score: not measured", foreground="")
            self.lbl_summary.configure(text="No devices tested yet.")

        if s.diagnosis:
            fill(self.tree_diag, [((r.stage, r.name, r.layer, r.status, r.detail or r.hint),
                                   "bad" if r.status == "Failed" else "") for r in s.diagnosis.results])
            self.lbl_diag.configure(text=s.diagnosis.summary)

        fill(self.tree_recs, [((r.severity, r.category, r.target, r.message),
                               "warn" if r.severity == "Warning" else "") for r in s.recommendations])
        self._update_alert_bar()

    def _update_alert_bar(self):
        s = self.session
        parts = []
        n = sum(x.unreachable for x in s.stats)
        parts += [f"{n} unreachable"] if n else []
        n = sum(x.high_loss for x in s.stats)
        parts += [f"{n} with weak connectivity"] if n else []
        n = sum(r.category == "High latency" for r in s.recommendations)
        parts += [f"{n} with high latency"] if n else []
        n = sum(r.category == "Potentially risky service" for r in s.recommendations)
        parts += [f"{n} risky service(s) open"] if n else []
        n = len(s.unknown_devices or [])
        parts += [f"{n} unknown device(s)"] if n else []
        if s.baseline_error:
            parts.append("baseline file unreadable")
        if parts:
            self.alert.configure(text="Alerts: " + "  |  ".join(parts), bg=WARN[0], fg=WARN[1])
        elif s.stats:
            self.alert.configure(text="No alerts: all tested devices meet the thresholds.",
                                 bg="#e3f4e8", fg="#1e7e34")
        else:
            self.alert.configure(text="", bg=self.cget("bg"))


def run() -> None:
    NetDoctorApp().mainloop()
