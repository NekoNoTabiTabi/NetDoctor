"""Tkinter interface (report, "Graphical interface").

Shows: local IP, network range, default gateway, discovered-device list,
performance statistics, diagnostic output, security recommendations and the
network health score. Devices can be multi-selected for testing.

Look and feel: a "clinic chart" theme (warm paper, ink sidebar, one coral
accent). Standard library only: every widget is Tk/ttk, the health ring, the
link-pulse monitor and the diagnosis timeline are drawn on canvases.

Threading: scanning/measuring run in worker threads. Workers never touch
widgets; they put messages on ``self.queue`` and the main thread drains it in
``_poll_queue``. Unreachable devices and devices with high packet loss are
highlighted.
"""

from __future__ import annotations

import logging
import queue
import random
import threading
import tkinter as tk
from collections import deque
from tkinter import font as tkfont
from tkinter import messagebox, ttk
from typing import Callable, Optional

from . import config
from .baseline import BaselineError
from .discovery import DiscoveryError
from .pinger import PingError
from .report import ReportError
from .session import MonitoringSession
from .stats import TABLE_HEADERS

log = logging.getLogger(__name__)

# ------------------------------------------------------------------ palette
INK, INK_2, INK_FG, INK_MUTED = "#18212B", "#243241", "#E9E4D8", "#8E9AA8"
PAPER, CARD, ZEBRA, LINE = "#F3EFE6", "#FFFDF8", "#FAF6EC", "#DED7C7"
TEXT, MUTED = "#1B2430", "#7B7566"
ACCENT, ACCENT_DK, ACCENT_LT = "#E4572E", "#C74522", "#F6D9CF"
OK, WARN, BAD = "#2F8F5B", "#B97800", "#C2362B"
CHIP = {"ok": ("#E1F0E6", OK), "warn": ("#FBEBC8", WARN),
        "bad": ("#F8DAD5", BAD), "info": ("#E8E3D6", "#4A4538")}
ROW = {"bad": ("#FBE3E0", "#8C1C13"), "warn": ("#FDF0D5", "#7A4B00")}
RATING_COLORS = {"Excellent": OK, "Good": "#3E9B6B", "Fair": WARN, "Poor": BAD}
EXPECTED_ERRORS = (DiscoveryError, PingError, BaselineError, ReportError, ValueError)

AUTH_NOTICE = ("NetDoctor sends ping requests and TCP connection attempts.\n\n"
               "Use it only on networks and devices you own or are authorised to assess.\n\n"
               "Continue?")

PAGES = (("devices", "Devices"), ("stats", "Statistics"),
         ("diag", "Diagnosis"), ("recs", "Security"))

# One heartbeat (P wave, QRS complex, T wave), drawn by the link-pulse monitor.
BEAT = (0, 0, .05, .12, .17, .12, .05, 0, 0, -.1, .18, 1.0, .3, -.32, -.08, 0, 0,
        .05, .12, .2, .26, .28, .24, .16, .08, .02, 0)
PULSE = {   # mode: (trace colour, caption)
    "idle": ("#6F7C8C", "AWAITING SIGNAL"), "busy": ("#FF8A65", "PROBING"),
    "ok": ("#5EDC9A", "STEADY"), "warn": ("#F2B84B", "IRREGULAR"),
    "bad": ("#FF6B5E", "CRITICAL")}


def pick_font(options, fallback):
    have = set(tkfont.families())
    return next((f for f in options if f in have), fallback)


def make_tree(parent, columns, widths, empty_text, selectmode="browse") -> ttk.Treeview:
    """A flat table with a thin scrollbar and a friendly empty state."""
    frame = tk.Frame(parent, bg=CARD)
    frame.pack(fill="both", expand=True)
    tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode=selectmode,
                        style="Chart.Treeview")
    for col in columns:
        tree.heading(col, text=col.upper(), anchor="w")
        tree.column(col, width=widths.get(col, 120), anchor="w")
    scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview,
                           style="Chart.Vertical.TScrollbar")

    def on_scroll(first, last):          # hide the scrollbar when every row fits
        scroll.set(first, last)
        if float(first) <= 0 and float(last) >= 1:
            scroll.pack_forget()
        elif not scroll.winfo_ismapped():
            scroll.pack(side="right", fill="y", before=tree)

    tree.configure(yscrollcommand=on_scroll)
    tree.pack(side="left", fill="both", expand=True)
    tree.tag_configure("even", background=CARD)
    tree.tag_configure("odd", background=ZEBRA)
    for tag, (bg, fg) in ROW.items():
        tree.tag_configure(tag, background=bg, foreground=fg)
    tree._empty = tk.Label(frame, text=empty_text, bg=CARD, fg=MUTED, justify="center",
                           font=(pick_font(("Georgia", "DejaVu Serif"), "serif"), 12, "italic"))
    tree._empty.place(relx=.5, rely=.4, anchor="center")
    return tree


def fill(tree: ttk.Treeview, rows) -> None:
    """Replace the content of ``tree``; each row is ``(values, tag)``."""
    tree.delete(*tree.get_children())
    for i, (values, tag) in enumerate(rows):
        tree.insert("", "end", values=values, tags=(tag or ("odd" if i % 2 else "even"),))
    if rows:
        tree._empty.place_forget()
    else:
        tree._empty.place(relx=.5, rely=.4, anchor="center")


class NetDoctorApp(tk.Tk):
    DEVICE_COLS = ("Hostname", "IP Address", "MAC Address", "Vendor", "Detected via",
                   "Status", "Trust")
    RING = 132

    def __init__(self, session: Optional[MonitoringSession] = None):
        super().__init__()
        self.title(config.APP_TITLE)
        self.geometry("1260x800")
        self.minsize(1040, 680)
        self.configure(bg=PAPER)
        self.session = session or MonitoringSession()
        self.queue: "queue.Queue" = queue.Queue()
        self.busy = False
        self.acknowledged = False

        self.f_sans = pick_font(("Segoe UI", "Inter", "SF Pro Text", "Helvetica Neue",
                                 "DejaVu Sans"), "sans-serif")
        self.f_serif = pick_font(("Georgia", "Palatino Linotype", "DejaVu Serif"), "serif")
        self.f_mono = pick_font(("Cascadia Mono", "Consolas", "SF Mono", "DejaVu Sans Mono"),
                                "monospace")
        self._ring_value = self._ring_target = 0.0
        self._ring_color, self._ring_anim = "#CFC8B6", None
        self._ecg = deque(maxlen=400)
        self._ecg_queue: deque = deque()
        self._ecg_mode = "idle"
        self.page = "devices"

        self._build_styles()
        self._build_status_bar()
        self._build_sidebar()
        main = tk.Frame(self, bg=PAPER)
        main.pack(side="left", fill="both", expand=True, padx=26, pady=(20, 8))
        self._build_command_bar(main)
        self._build_chips(main)
        self._build_vitals(main)
        self._build_pages(main)
        self._show_page("devices")
        self._draw_ring(0)
        self.after(100, self._poll_queue)
        self.after(40, self._tick_pulse)
        self.after(300, self.detect_network)

    # ----------------------------------------------------------------- styles
    def _build_styles(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        body = (self.f_sans, 10)
        st.configure("Chart.Treeview", background=CARD, fieldbackground=CARD,
                     foreground=TEXT, rowheight=32, borderwidth=0, font=body)
        st.layout("Chart.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        st.map("Chart.Treeview", background=[("selected", ACCENT_LT)],
               foreground=[("selected", TEXT)])
        st.configure("Chart.Treeview.Heading", background="#EDE6D6", foreground=MUTED,
                     relief="flat", borderwidth=0, padding=(10, 8),
                     font=(self.f_sans, 8, "bold"))
        st.map("Chart.Treeview.Heading", background=[("active", "#E4DBC7")])
        st.layout("Chart.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
            "sticky": "ns", "children": [("Vertical.Scrollbar.thumb",
                                          {"expand": "1", "sticky": "nswe"})]})])
        st.configure("Chart.Vertical.TScrollbar", troughcolor=CARD, background=LINE,
                     bordercolor=CARD, lightcolor=LINE, darkcolor=LINE, width=9)
        st.map("Chart.Vertical.TScrollbar", background=[("active", "#C9C1AE")])
        for name, bg, fg, hover, bd in (
                ("Primary", ACCENT, "#FFFFFF", ACCENT_DK, ACCENT),
                ("Ghost", CARD, TEXT, "#EFE9DB", LINE)):
            st.configure(f"{name}.TButton", background=bg, foreground=fg, bordercolor=bd,
                         lightcolor=bg, darkcolor=bg, focuscolor=bg, borderwidth=1,
                         padding=(16, 9), font=(self.f_sans, 10, "bold"), relief="flat")
            st.map(f"{name}.TButton", background=[("disabled", "#E9E3D5"), ("active", hover)],
                   foreground=[("disabled", "#A8A290")], bordercolor=[("disabled", LINE)])
        st.configure("Chart.TEntry", fieldbackground=CARD, bordercolor=LINE,
                     lightcolor=LINE, darkcolor=LINE, padding=8, foreground=TEXT,
                     insertcolor=TEXT)
        st.map("Chart.TEntry", bordercolor=[("focus", ACCENT)], lightcolor=[("focus", ACCENT)])
        st.configure("Chart.Horizontal.TProgressbar", troughcolor="#E4DDCC",
                     background=ACCENT, bordercolor=PAPER, lightcolor=ACCENT,
                     darkcolor=ACCENT, thickness=6)

    # ---------------------------------------------------------------- sidebar
    def _build_sidebar(self):
        side = tk.Frame(self, bg=INK, width=236)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        brand = tk.Frame(side, bg=INK)
        brand.pack(fill="x", padx=22, pady=(26, 22))
        logo = tk.Canvas(brand, width=34, height=34, bg=INK, highlightthickness=0)
        logo.create_oval(1, 1, 33, 33, outline=ACCENT, width=2)
        logo.create_line(5, 18, 12, 18, 16, 8, 21, 27, 24, 18, 29, 18, fill=ACCENT,
                         width=2, joinstyle="round", capstyle="round")
        logo.pack(side="left")
        names = tk.Frame(brand, bg=INK)
        names.pack(side="left", padx=11)
        tk.Label(names, text="NetDoctor", bg=INK, fg="#FFFFFF",
                 font=(self.f_serif, 17, "bold")).pack(anchor="w")
        tk.Label(names, text="network clinic", bg=INK, fg=INK_MUTED,
                 font=(self.f_sans, 9)).pack(anchor="w")

        self.nav = {}
        for key, label in PAGES:
            row = tk.Frame(side, bg=INK, cursor="hand2")
            row.pack(fill="x", pady=1)
            bar = tk.Frame(row, bg=INK, width=4)
            bar.pack(side="left", fill="y")
            text = tk.Label(row, text=label, bg=INK, fg=INK_FG, anchor="w", padx=18,
                            pady=11, font=(self.f_sans, 11))
            text.pack(side="left", fill="x", expand=True)
            badge = tk.Label(row, text="", bg=INK, fg=INK_MUTED, padx=8,
                             font=(self.f_mono, 9, "bold"))
            badge.pack(side="right", padx=(0, 12))
            self.nav[key] = (row, bar, text, badge)
            for w in (row, text, badge):
                w.bind("<Button-1>", lambda _e, k=key: self._show_page(k))
                w.bind("<Enter>", lambda _e, k=key: self._style_nav(hover=k))
                w.bind("<Leave>", lambda _e: self._style_nav())

        tk.Label(side, text="Use only on networks you are\nauthorised to assess.",
                 bg=INK, fg="#5F6C7A", justify="left", font=(self.f_sans, 8)
                 ).pack(side="bottom", anchor="w", padx=22, pady=(0, 18))
        info = tk.Frame(side, bg=INK)
        info.pack(side="bottom", fill="x", padx=22, pady=(0, 18))
        tk.Frame(info, bg=INK_2, height=1).pack(fill="x", pady=(0, 14))
        self.lbl_ip = self._info_row(info, "THIS HOST")
        self.lbl_net = self._info_row(info, "SUBNET")
        self.lbl_gw = self._info_row(info, "GATEWAY")

    def _info_row(self, parent, caption) -> tk.Label:
        tk.Label(parent, text=caption, bg=INK, fg=INK_MUTED, anchor="w",
                 font=(self.f_sans, 8, "bold")).pack(fill="x")
        value = tk.Label(parent, text="...", bg=INK, fg=INK_FG, anchor="w",
                         font=(self.f_mono, 11))
        value.pack(fill="x", pady=(0, 10))
        return value

    def _style_nav(self, hover: Optional[str] = None):
        for key, (row, bar, text, badge) in self.nav.items():
            active = key == self.page
            bg = INK_2 if active or key == hover else INK
            for w in (row, text, badge):
                w.configure(bg=bg)
            bar.configure(bg=ACCENT if active else bg)
            text.configure(fg="#FFFFFF" if active else INK_FG,
                           font=(self.f_sans, 11, "bold" if active else "normal"))

    # ------------------------------------------------------------ command bar
    def _build_command_bar(self, parent):
        bar = tk.Frame(parent, bg=PAPER)
        bar.pack(fill="x")
        tk.Label(bar, text="RANGE", bg=PAPER, fg=MUTED,
                 font=(self.f_sans, 8, "bold")).pack(side="left", padx=(0, 8))
        self.range_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.range_var, width=17, style="Chart.TEntry",
                  font=(self.f_mono, 10)).pack(side="left", padx=(0, 16))
        self.buttons = []
        for text, cmd, style in (("Scan network", self.scan, "Primary"),
                                 ("Test selected", self.test_selected, "Ghost"),
                                 ("Run diagnosis", self.run_diagnosis, "Ghost"),
                                 ("Save baseline", self.save_baseline, "Ghost"),
                                 ("Generate report", self.generate_report, "Ghost")):
            btn = ttk.Button(bar, text=text, command=cmd, style=f"{style}.TButton")
            btn.pack(side="left", padx=(0, 8))
            self.buttons.append(btn)

    def _build_chips(self, parent):
        self.chips = tk.Frame(parent, bg=PAPER, height=40)
        self.chips.pack(fill="x", pady=(12, 0))
        self.chips.pack_propagate(False)

    def _set_chips(self, items):
        for w in self.chips.winfo_children():
            w.destroy()
        for text, kind in items:
            bg, fg = CHIP[kind]
            tk.Label(self.chips, text=text, bg=bg, fg=fg, padx=11, pady=4,
                     font=(self.f_sans, 9, "bold")).pack(side="left", padx=(0, 8), pady=6)

    # ----------------------------------------------------------------- vitals
    def _card(self, parent, **kw) -> tk.Frame:
        return tk.Frame(parent, bg=CARD, highlightbackground=LINE, highlightthickness=1, **kw)

    def _build_vitals(self, parent):
        card = self._card(parent)
        card.pack(fill="x")
        card.columnconfigure(2, weight=1)

        self.ring = tk.Canvas(card, width=self.RING, height=self.RING, bg=CARD,
                              highlightthickness=0)
        self.ring.grid(row=0, column=0, padx=(18, 10), pady=14)

        mid = tk.Frame(card, bg=CARD)
        mid.grid(row=0, column=1, padx=(6, 22), sticky="ns", pady=14)
        tk.Label(mid, text="NETWORK HEALTH", bg=CARD, fg=MUTED,
                 font=(self.f_sans, 8, "bold")).pack(anchor="w")
        self.lbl_rating = tk.Label(mid, text="Not measured", bg=CARD, fg=TEXT,
                                   font=(self.f_serif, 19, "bold"))
        self.lbl_rating.pack(anchor="w", pady=(0, 6))
        self.bars = {}
        for key, label in (("reach", "Reachability"), ("loss", "Packet loss"),
                           ("lat", "Latency")):
            line = tk.Frame(mid, bg=CARD)
            line.pack(fill="x", pady=2)
            tk.Label(line, text=label, bg=CARD, fg=TEXT, width=12, anchor="w",
                     font=(self.f_sans, 9)).pack(side="left")
            bar = tk.Canvas(line, width=120, height=8, bg=CARD, highlightthickness=0)
            bar.pack(side="left", padx=6)
            pts = tk.Label(line, text="-", bg=CARD, fg=MUTED, width=7, anchor="e",
                           font=(self.f_mono, 9))
            pts.pack(side="left")
            self.bars[key] = (bar, pts)
            self._draw_bar(bar, 0, "#CFC8B6")
        self.lbl_summary = tk.Label(mid, text="No devices tested yet.", bg=CARD, fg=MUTED,
                                    anchor="w", font=(self.f_sans, 9))
        self.lbl_summary.pack(anchor="w", pady=(6, 0))

        monitor = tk.Frame(card, bg="#10171F")
        monitor.grid(row=0, column=2, sticky="nsew", padx=(0, 14), pady=14)
        self.ecg = tk.Canvas(monitor, height=self.RING, bg="#10171F", highlightthickness=0)
        self.ecg.pack(fill="both", expand=True)
        self.ecg.bind("<Configure>", self._draw_ecg_grid)

    def _draw_bar(self, canvas, frac, color):
        canvas.delete("all")
        canvas.create_rectangle(0, 0, 120, 8, fill="#E9E3D4", outline="")
        if frac > 0:
            canvas.create_rectangle(0, 0, max(3, 120 * frac), 8, fill=color, outline="")

    def _draw_ring(self, value):
        c, s, pad = self.ring, self.RING, 13
        c.delete("all")
        box = (pad, pad, s - pad, s - pad)
        c.create_oval(*box, outline="#E9E3D4", width=11)
        if value > 0:
            c.create_arc(*box, start=90, extent=-min(359.9, value * 3.6), style="arc",
                         outline=self._ring_color, width=11)
        measured = self.session.health is not None
        c.create_text(s / 2, s / 2 - 5, text=str(round(value)) if measured else "-",
                      fill=TEXT, font=(self.f_serif, 30, "bold"))
        c.create_text(s / 2, s / 2 + 23, text="OUT OF 100", fill=MUTED,
                      font=(self.f_sans, 7, "bold"))

    def _set_ring(self, score: Optional[int], color: str):
        self._ring_target, self._ring_color = float(score or 0), color
        if self._ring_anim is None:
            self._ring_step()

    def _ring_step(self):
        diff = self._ring_target - self._ring_value
        if abs(diff) < 0.8:
            self._ring_value, self._ring_anim = self._ring_target, None
        else:
            self._ring_value += diff * 0.16
            self._ring_anim = self.after(16, self._ring_step)
        self._draw_ring(self._ring_value)

    # ------------------------------------------------------- link-pulse trace
    def _draw_ecg_grid(self, _event=None):
        c = self.ecg
        w, h = c.winfo_width(), c.winfo_height()
        c.delete("grid")
        for x in range(0, w, 22):
            c.create_line(x, 0, x, h, fill="#17212C", tags="grid")
        for y in range(0, h, 22):
            c.create_line(0, y, w, y, fill="#17212C", tags="grid")
        c.tag_lower("grid")

    def _pulse_mode(self) -> str:
        s = self.session
        if self.busy:
            return "busy"
        if s.health:
            return {"Excellent": "ok", "Good": "ok", "Fair": "warn"}.get(s.health.rating, "bad")
        if s.diagnosis:
            return "ok" if s.diagnosis.passed else "bad"
        return "idle"

    def _more_samples(self, mode):
        if mode == "ok":
            return list(BEAT) + [0] * 22
        if mode == "busy":
            return [v * .9 for v in BEAT] + [0] * 3
        if mode == "warn":
            amp = .5 + random.random() * .6
            return [v * amp for v in BEAT] + [0] * random.randint(3, 30)
        if mode == "bad":
            return [0] * 20 + ([.12, -.08, .04] if random.random() < .25 else [0] * 3)
        return [(random.random() - .5) * .03 for _ in range(30)]

    def _tick_pulse(self):
        try:
            mode = self._pulse_mode()
            if mode != self._ecg_mode:
                self._ecg_mode = mode
                self._ecg_queue.clear()
            if not self._ecg_queue:
                self._ecg_queue.extend(self._more_samples(mode))
            self._ecg.append(self._ecg_queue.popleft())
            c = self.ecg
            w, h = c.winfo_width(), c.winfo_height()
            step = 3
            samples = list(self._ecg)[-(w // step + 2):]
            n = len(samples)
            pts = []
            for i, v in enumerate(samples):
                pts += [w - (n - 1 - i) * step, h * .56 - v * h * .36]
            c.delete("trace", "caption")
            color, caption = PULSE[mode]
            if n > 1:
                c.create_line(*pts, fill=color, width=2, joinstyle="round",
                              capstyle="round", tags="trace")
            c.create_text(14, 14, text="LINK PULSE", anchor="w", fill="#5F6C7A", tags="caption",
                          font=(self.f_sans, 8, "bold"))
            c.create_text(w - 14, 14, text=caption, anchor="e", fill=color, tags="caption",
                          font=(self.f_mono, 9, "bold"))
            self.after(36, self._tick_pulse)
        except tk.TclError:                       # window closed
            return

    # ------------------------------------------------------------------ pages
    def _build_pages(self, parent):
        self.pages_card = self._card(parent)
        self.pages_card.pack(fill="both", expand=True, pady=(14, 0))
        self.pages_card.rowconfigure(0, weight=1)
        self.pages_card.columnconfigure(0, weight=1)
        self.frames = {}
        for key, _ in PAGES:
            f = tk.Frame(self.pages_card, bg=CARD)
            f.grid(row=0, column=0, sticky="nsew")
            self.frames[key] = f

        # Devices (multi-select: "Users can select multiple devices")
        self.lbl_devices = self._page_header(self.frames["devices"], "Devices on the network",
                                             "Ctrl/Shift-click to select several")
        self.tree_devices = make_tree(
            self.frames["devices"], self.DEVICE_COLS,
            {"Hostname": 140, "IP Address": 125, "MAC Address": 140, "Vendor": 195,
             "Detected via": 95, "Status": 105, "Trust": 120},
            "Nothing scanned yet.\nPress Scan network to see who is on the line.",
            selectmode="extended")

        # Statistics
        self.lbl_tested = self._page_header(self.frames["stats"], "Measured performance",
                                            "10 pings per device + TCP port checks")
        self.tree_stats = make_tree(
            self.frames["stats"], TABLE_HEADERS,
            {"Hostname": 200, "IP Address": 120, "Average Latency (ms)": 150,
             "Maximum Latency (ms)": 150, "Minimum Latency (ms)": 150,
             "Packet Loss (%)": 120, "Status": 90},
            "No measurements yet.\nSelect devices, then press Test selected.")

        # Diagnosis: a vertical timeline instead of a table
        self._page_header(self.frames["diag"], "Layer-by-layer diagnosis",
                          "stops at the first failed check")
        self.lbl_diag = tk.Label(self.frames["diag"], text="Diagnosis not run.", bg=CARD,
                                 fg=MUTED, anchor="w", justify="left",
                                 font=(self.f_sans, 10))
        self.lbl_diag.pack(fill="x", padx=20, pady=(0, 2))
        self.canvas_diag = tk.Canvas(self.frames["diag"], bg=CARD, highlightthickness=0)
        self.canvas_diag.pack(fill="both", expand=True)
        self.canvas_diag.bind("<Configure>", lambda e: self._draw_diagnosis())
        self.frames["diag"].bind("<Configure>",
                                 lambda e: self.lbl_diag.configure(wraplength=max(300, e.width - 40)))

        # Security
        self._page_header(self.frames["recs"], "Security recommendations",
                          "select a row to read it in full")
        self.tree_recs = make_tree(
            self.frames["recs"], ("Severity", "Category", "Target", "Recommendation"),
            {"Severity": 100, "Category": 190, "Target": 130, "Recommendation": 700},
            "No recommendations yet.\nScan and test devices to get advice.")
        detail = tk.Frame(self.frames["recs"], bg="#F7F1E3")
        detail.pack(fill="x", side="bottom")
        tk.Frame(detail, bg=ACCENT, width=4).pack(side="left", fill="y")
        self.lbl_rec_detail = tk.Label(detail, text="Select a recommendation to read it in full.",
                                       bg="#F7F1E3", fg=TEXT, justify="left", anchor="w",
                                       padx=16, pady=12, font=(self.f_sans, 10))
        self.lbl_rec_detail.pack(fill="x", side="left", expand=True)
        detail.bind("<Configure>", lambda e: self.lbl_rec_detail.configure(
            wraplength=max(300, e.width - 60)))
        self.tree_recs.bind("<<TreeviewSelect>>", self._show_recommendation)

    def _page_header(self, parent, title, hint) -> tk.Label:
        head = tk.Frame(parent, bg=CARD)
        head.pack(fill="x", padx=20, pady=(14, 8))
        tk.Label(head, text=title, bg=CARD, fg=TEXT,
                 font=(self.f_serif, 14, "bold")).pack(side="left")
        count = tk.Label(head, text="", bg=CARD, fg=ACCENT, font=(self.f_mono, 10, "bold"))
        count.pack(side="left", padx=12)
        tk.Label(head, text=hint, bg=CARD, fg=MUTED, font=(self.f_sans, 9)).pack(side="right")
        return count

    def _show_page(self, key: str):
        self.page = key
        self.frames[key].tkraise()
        self._style_nav()

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=PAPER, highlightbackground=LINE, highlightthickness=1)
        bar.pack(fill="x", side="bottom")
        self.status = tk.Label(bar, text="Ready", bg=PAPER, fg=MUTED, anchor="w", padx=18,
                               pady=6, font=(self.f_sans, 9))
        self.status.pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(bar, length=220, mode="determinate",
                                        style="Chart.Horizontal.TProgressbar")
        self.progress.pack(side="right", padx=18)

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
    def _show_network(self, ip, net, gw):
        self.lbl_ip.configure(text=ip)
        self.lbl_net.configure(text=net)
        self.lbl_gw.configure(text=gw or "not detected")

    def detect_network(self):
        def done(info):
            ip, net, gw = info
            self._show_network(ip, net, gw)
            self.range_var.set(net)
            self.status.configure(text="Ready. Press 'Scan network' to find devices.")
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
            self._show_network(self.session.local_ip, self.session.network, self.session.gateway)
            self.refresh()
            self._show_page("devices")
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
                                   "Select one or more devices on the Devices page first "
                                   "(Ctrl/Shift-click for several).")
            return

        def done(_):
            self.refresh()
            self._show_page("stats")
            self.status.configure(text=f"Tested {len(ips)} device(s).")
        self._run_async(lambda p: self.session.measure(ips, p), done,
                        f"Testing {len(ips)} device(s): {config.PING_COUNT} ping requests each "
                        "+ TCP port checks (this takes about 15 seconds)...")

    def run_diagnosis(self):
        def work(progress):
            return self.session.diagnose()

        def done(result):
            self.refresh()
            self._show_page("diag")
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
            self.lbl_rec_detail.configure(text=f"{sev.split(' ', 1)[-1]}  |  {cat}  |  {target}\n{msg}")

    # --------------------------------------------------------------- rendering
    def _draw_diagnosis(self):
        c = self.canvas_diag
        c.delete("all")
        diag = self.session.diagnosis
        w = max(c.winfo_width(), 400)
        if not diag or not diag.results:
            c.create_text(w / 2, 90, fill=MUTED, justify="center",
                          font=(self.f_serif, 12, "italic"),
                          text="Not run yet.\nPress Run diagnosis to walk the stack from the bottom up.")
            return
        name_f = tkfont.Font(family=self.f_sans, size=11, weight="bold")
        pill_f = tkfont.Font(family=self.f_mono, size=8, weight="bold")
        x0, top, row_h = 44, 34, 64
        look = {"Passed": (OK, "✓"), "Failed": (BAD, "✕"), "Skipped": ("#B9B29F", "–")}
        for i, r in enumerate(diag.results):
            y = top + i * row_h
            color, glyph = look.get(r.status, ("#B9B29F", "–"))
            if i < len(diag.results) - 1:
                nxt = look.get(diag.results[i + 1].status, ("#B9B29F",))[0]
                c.create_line(x0, y + 14, x0, y + row_h - 14, fill=LINE if nxt != OK else "#BFDCCB",
                              width=3)
            c.create_oval(x0 - 14, y - 14, x0 + 14, y + 14, fill=color, outline="")
            c.create_text(x0, y - 1, text=glyph, fill="#FFFFFF", font=(self.f_sans, 12, "bold"))
            c.create_text(x0 + 34, y - 9, text=r.name, anchor="w", fill=TEXT, font=name_f)
            px = x0 + 34 + name_f.measure(r.name) + 14
            tw = pill_f.measure(r.layer.upper()) + 16
            c.create_rectangle(px, y - 18, px + tw, y, fill="#EDE6D6", outline="")
            c.create_text(px + tw / 2, y - 9, text=r.layer.upper(), fill=MUTED, font=pill_f)
            c.create_text(x0 + 34, y + 13, anchor="w", width=w - 120,
                          text=r.detail or r.hint, fill=BAD if r.status == "Failed" else MUTED,
                          font=(self.f_sans, 10))

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
            dot = {"Online": "●", "Unreachable": "○", "ARP only": "◐"}.get(status, "●")
            mark = {"Trusted": "✓ ", "UNKNOWN": "▲ "}.get(trust, "")
            rows.append(((d.hostname, d.ip, d.mac or "-", d.vendor, d.via,
                          f"{dot} {status}", f"{mark}{trust}"), tag))
        fill(self.tree_devices, rows)
        self.tree_devices.selection_set([i for i in self.tree_devices.get_children()
                                         if self.tree_devices.item(i, "values")[1] in keep_selected])
        self.lbl_devices.configure(text=f"{len(s.devices)} found" if s.devices else "")

        fill(self.tree_stats, [(x.as_row(), "bad" if x.unreachable else "warn" if x.high_loss else "")
                               for x in s.stats])
        self.lbl_tested.configure(text=f"{len(s.stats)} tested" if s.stats else "")

        self._refresh_health()

        if s.diagnosis:
            self.lbl_diag.configure(text=s.diagnosis.summary,
                                    fg=OK if s.diagnosis.passed else BAD)
        self._draw_diagnosis()

        fill(self.tree_recs, [((("▲ " if r.severity == "Warning" else "● ") + r.severity,
                                r.category, r.target, r.message),
                               "warn" if r.severity == "Warning" else "") for r in s.recommendations])
        self._update_alerts()
        self._update_badges()

    def _refresh_health(self):
        h = self.session.health
        if not h:
            self._set_ring(None, "#CFC8B6")
            self.lbl_rating.configure(text="Not measured", fg=TEXT)
            self.lbl_summary.configure(text="No devices tested yet.")
            for bar, pts in self.bars.values():
                self._draw_bar(bar, 0, "#CFC8B6")
                pts.configure(text="-")
            return
        color = RATING_COLORS[h.rating]
        self._set_ring(h.score, color)
        self.lbl_rating.configure(text=h.rating, fg=color)
        for key, got, top in (("reach", h.reachability_pts, config.REACHABILITY_POINTS),
                              ("loss", h.loss_pts, config.LOSS_POINTS),
                              ("lat", h.latency_pts, config.LATENCY_POINTS)):
            bar, pts = self.bars[key]
            self._draw_bar(bar, got / top, color)
            pts.configure(text=f"{got:g}/{top}")
        lat = "N/A" if h.avg_latency_ms is None else f"{h.avg_latency_ms} ms"
        self.lbl_summary.configure(text=(f"{h.responding}/{h.tested} responding   "
                                         f"loss {h.avg_loss_pct}%   latency {lat}"))

    def _update_alerts(self):
        s = self.session
        items = []
        n = sum(x.unreachable for x in s.stats)
        items += [(f"{n} unreachable", "bad")] if n else []
        n = sum(x.high_loss for x in s.stats)
        items += [(f"{n} with weak connectivity", "warn")] if n else []
        n = sum(r.category == "High latency" for r in s.recommendations)
        items += [(f"{n} with high latency", "warn")] if n else []
        n = sum(r.category == "Potentially risky service" for r in s.recommendations)
        items += [(f"{n} risky service(s) open", "bad")] if n else []
        n = len(s.unknown_devices or [])
        items += [(f"{n} unknown device(s)", "warn")] if n else []
        if s.baseline_error:
            items.append(("baseline file unreadable", "bad"))
        if not items and s.stats:
            items = [("All tested devices meet the thresholds", "ok")]
        self._set_chips(items)

    def _update_badges(self):
        s = self.session
        warnings = sum(r.severity == "Warning" for r in s.recommendations)
        texts = {"devices": str(len(s.devices)) if s.devices else "",
                 "stats": str(len(s.stats)) if s.stats else "",
                 "diag": "" if not s.diagnosis else "✓" if s.diagnosis.passed else "✕",
                 "recs": str(warnings) if warnings else ""}
        for key, text in texts.items():
            self.nav[key][3].configure(text=text)


def run() -> None:
    NetDoctorApp().mainloop()
