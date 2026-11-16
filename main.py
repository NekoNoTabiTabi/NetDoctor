"""NetDoctor entry point.

    python main.py                 start the Tkinter GUI
    python main.py --cli           console mode: monitor (scan, test, report)
    python main.py --cli --diagnose   console mode: layer-by-layer diagnosis only
"""

from __future__ import annotations

import argparse
import logging
import sys
from logging.handlers import RotatingFileHandler

from netdoctor import config


def setup_logging(verbose: bool = False) -> None:
    """Rotating log file (logs/netdoctor.log); warnings also go to stderr."""
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    fh = RotatingFileHandler(config.LOG_DIR / "netdoctor.log", maxBytes=500_000,
                             backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setLevel(logging.WARNING)
    sh.setFormatter(fmt)
    root.addHandler(sh)


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="netdoctor", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cli", action="store_true", help="run in console mode")
    p.add_argument("--diagnose", action="store_true",
                   help="(console) run only the layer-by-layer diagnosis")
    p.add_argument("--network", metavar="CIDR", help="(console) range to scan, e.g. 192.168.1.0/24")
    p.add_argument("--prefix", type=int, default=config.DEFAULT_PREFIX,
                   help=f"prefix length for the detected network (default /{config.DEFAULT_PREFIX})")
    p.add_argument("--devices", metavar="IP[,IP...]",
                   help="(console) devices to test; default: all detected")
    p.add_argument("--save-baseline", action="store_true",
                   help="(console) save the detected devices as the trusted baseline")
    p.add_argument("--no-report", action="store_true", help="(console) do not write report files")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return p.parse_args(argv)


def run_cli(args: argparse.Namespace) -> int:
    from netdoctor.baseline import BaselineError
    from netdoctor.diagnostics import DiagnosisResult
    from netdoctor.discovery import DiscoveryError
    from netdoctor.pinger import PingError
    from netdoctor.report import ReportError, text_table
    from netdoctor.session import MonitoringSession
    from netdoctor.stats import TABLE_HEADERS

    def show_diagnosis(d: DiagnosisResult) -> None:
        print(text_table(("Stage", "Check", "Result", "Detail"),
                         [(r.stage, r.name, r.status, r.detail) for r in d.results]))
        print("\n" + d.summary)

    print("NetDoctor: use only on networks you own or are authorised to assess.\n")
    session = MonitoringSession(prefix=args.prefix)
    try:
        if args.diagnose:
            show_diagnosis(session.diagnose())
            return 0 if session.diagnosis.passed else 2

        ip, net, gw = session.detect_network(args.network)
        print(f"Local IP: {ip}\nNetwork range: {net}\nDefault gateway: {gw or 'not detected'}\n")
        print("Scanning (ping sweep + ARP table)...")
        devices = session.scan()
        if not devices:
            print("No devices detected.")
            return 1
        print(text_table(("Hostname", "IP Address", "MAC Address", "Vendor", "Detected via", "Status"),
                         [(d.hostname, d.ip, d.mac or "-", d.vendor, d.via, d.status)
                          for d in devices]))

        selected = ([x.strip() for x in args.devices.split(",") if x.strip()]
                    if args.devices else [d.ip for d in devices])
        print(f"\nTesting {len(selected)} device(s): {config.PING_COUNT} ping requests each "
              "+ TCP port checks...")
        session.measure(selected)
        print(text_table(TABLE_HEADERS, [s.as_row() for s in session.stats]))

        h = session.health
        print(f"\nNetwork Health Score: {h.score} / 100 ({h.rating})")
        warnings = [r for r in session.recommendations if r.severity == "Warning"]
        print(f"\nSecurity recommendations ({len(warnings)} warning(s)):")
        for r in session.recommendations:
            print(f"  [{r.severity}] {r.category} - {r.target}: {r.message}")

        if args.save_baseline:
            print(f"\nTrusted baseline saved ({session.save_baseline()} devices).")
        if not args.no_report:
            txt, htm = session.generate_report()
            print(f"\nReport written:\n  {txt}\n  {htm}")
        return 0
    except (DiscoveryError, PingError, BaselineError, ReportError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


def main(argv=None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    if args.cli:
        return run_cli(args)
    try:
        from netdoctor.gui import run
    except ImportError as exc:                    # tkinter not installed
        print(f"The graphical interface needs Tkinter ({exc}).\n"
              "Install it (Linux: sudo apt install python3-tk) or use: python main.py --cli",
              file=sys.stderr)
        return 1
    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
