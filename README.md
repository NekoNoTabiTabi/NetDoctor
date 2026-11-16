# NetDoctor - Network Monitoring and Performance Analysis System

Python 3.9+ (standard library only). Implements the *NetDoctor Final Technical Report*; see
`docs/GAP_ANALYSIS.md` for how each documented requirement is met and which choices are
implementation decisions.

## Run

```bash
python main.py                    # Tkinter GUI
python main.py --cli              # console mode: scan, test, score, report
python main.py --cli --diagnose   # layer-by-layer diagnosis only
python main.py --cli --network 192.168.1.0/28 --devices 192.168.1.1 --save-baseline
```

No `pip install` is needed. Tkinter ships with the python.org installers; on Linux:
`sudo apt install python3-tk iputils-ping net-tools`.
Administrator rights are **not** required.

Use only on networks and devices you own or are authorised to assess.

## Layout

```
main.py                 entry point (GUI, or --cli)
netdoctor/
  discovery.py          local IP, range (/24 default, max 1,022 hosts), gateway, ping sweep + ARP, hostnames
  pinger.py             OS ping, 10 requests, min/avg/max/jitter, loss from sent vs received
  stats.py              measure selected devices in parallel -> statistics table
  portscan.py           TCP checks on 21, 22, 23, 80, 443, 3389
  security.py           recommendations (100 % unreachable, >=20 % loss, >=100 ms, FTP/Telnet, unknown)
  health.py             network health score 0-100
  diagnostics.py        5-stage layer-by-layer diagnosis (stops at first failure)
  baseline.py           trusted-device baseline (JSON, MAC first, IP fallback)
  report.py             text + HTML reports
  oui.py                MAC prefix -> vendor
  gui.py                Tkinter interface (worker threads + queue)
  session.py            shared workflow used by GUI and console
  config.py             every threshold/default, tagged [DOC] or [IMPL]
tests/test_netdoctor.py 49 unittest cases
data/baseline.json      created when you save a baseline
reports/                generated .txt / .html reports
logs/netdoctor.log      rotating log
docs/                   GAP_ANALYSIS.md and GUI screenshots
```

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## GUI workflow

1. **Scan Network** - detects local IP, range, gateway; lists devices (hostname, IP, MAC, vendor, how detected, status, trust).
2. Select one or more devices (Ctrl/Shift-click) and **Test Selected Devices** - 10 pings each plus TCP port checks; statistics, health score and alerts update.
3. **Run Layer Diagnosis** - independent of the above.
4. **Save Trusted Baseline** - once you recognise every listed device.
5. **Generate Report** - writes `.txt` and `.html` (print the HTML to PDF if you need a PDF).
