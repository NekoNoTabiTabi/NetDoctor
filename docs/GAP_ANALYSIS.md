# NetDoctor - Documentation vs. Implementation Gap Analysis

**Source of truth:** *NetDoctor: Network Monitoring and Performance Analysis System - Final Technical Report (v2.3)* (text, Tables 1-3, Figures 1-3).
**Code reviewed:** `netmon` v1 (the project delivered earlier in this conversation). If you have a different code base, send it and the same method applies.
**Result:** v1 was built from a different brief. It matched about a third of the report. v2 (`netdoctor_project/`) implements the report; every deviation left in v2 is listed in Section 3.

---------------------------------------------------------------------------

## 1. Conflicts between the report and the original brief

The report wins. Each row says what changed in v2 and what you lose.

| # | Original brief / v1 | Report | v2 follows the report, so... |
|---|---|---|---|
| C1 | scapy, pandas, reportlab, customtkinter | Table 1: Python 3 **standard library only**, tkinter | All four third-party libraries removed. No `pip install` needed. |
| C2 | PDF report | "Reports are generated in text and HTML formats" | `report.py` writes `.txt` and `.html`. The HTML has print CSS, so a browser's *Print -> Save as PDF* gives a clean PDF. No native PDF. |
| C3 | SQLite scan history (3 tables) | State is `baseline.json` + report files only (Figure 1) | `database.py` and the History tab removed. |
| C4 | Ping count selectable 4-50 (default 4) | "sends **ten** ping requests" (Figure 2) | Fixed at `config.PING_COUNT = 10`; selector removed. |
| C5 | Min/Max/Avg latency required | Objective 3 lists avg, max, loss (no min); Table 2 says `pinger.py` computes min | Minimum kept as a column (superset of both). Remove it from `stats.TABLE_HEADERS` if you want Objective 3 literally. |
| C6 | 150 ms / 5 % / 25 % / 300 ms thresholds | 100 ms, 20 %, 100 % | Report thresholds only (G-10). |
| C7 | scapy ARP broadcast, ping-sweep fallback | Ping sweep **+ OS ARP cache** (Figure 2) | G-04. |

---------------------------------------------------------------------------

## 2. Gap analysis (documentation -> v1 -> gap -> change -> code -> test)

Code references are to `netdoctor_project/`. Whole-file replacements are not pasted here; the file is the "exact modification". Key excerpts are shown where the logic is the point.

### G-01 Package, module set and entry point
1. **Documentation:** Package `netdoctor`; Table 2 modules `main.py, pinger, discovery, stats, portscan, security, health, diagnostics, baseline, report, oui, gui`. `main.py --cli` starts console mode; GUI and console call the same core modules.
2. **v1:** Package `netmon` with `scanner, network_info, pinger, stats(pandas), security, database, report(reportlab), controller, gui/app(customtkinter)`; separate `cli.py`. No `portscan, health, diagnostics, baseline, oui`.
3. **Gap:** 5 documented modules missing, 3 undocumented modules present, wrong entry points.
4. **Change:** Rebuild as `netdoctor`; delete `scanner, network_info, database, controller, models, cli`; add the five missing modules; `main.py` handles `--cli`.
5. **Code:** `main.py`, `netdoctor/*.py`. One undocumented module remains on purpose: `session.py` (G-17).
6. **Test:** `python main.py` opens the GUI; `python main.py --cli` runs a full console monitor; `python main.py --cli --diagnose` runs diagnosis only.

### G-02 Local IP, network range, host limit
1. **Documentation:** UDP-socket local IP; `ipaddress`-based range with **/24 default** "unless configured otherwise"; discovery restricted to a **maximum of 1,022 host addresses**.
2. **v1:** Read the real netmask from `ip`/`ifconfig`/`ipconfig` (undocumented, three parsers); silently shrank oversized ranges toward /22; cap was 1,024.
3. **Gap:** Range logic differed from the documented default; the cap value was wrong; silent shrinking hid what was actually scanned.
4. **Change:** `get_network(ip, prefix=24)`; any range above 1,022 hosts raises a clear error instead of silently shrinking. `--prefix` is the documented "configured otherwise" hook.
5. **Code (`discovery.py`):**
```python
def _check_size(network):
    hosts = max(network.num_addresses - 2, 0)
    if hosts > config.MAX_HOSTS:                      # 1022
        raise DiscoveryError(f"{network} has {hosts} hosts; discovery is limited to "
                             f"{config.MAX_HOSTS} (use /22 or smaller).")
    return network
```
6. **Test:** Detect on a /24 LAN -> `x.x.x.0/24`. Enter `10.0.0.0/22` -> accepted. Enter `10.0.0.0/21` -> error dialog. `python main.py --cli --prefix 25` -> /25. (Unit: `DiscoveryTests.test_host_limit_1022`.)

### G-03 Default gateway
1. **Documentation:** `discovery.py` provides the gateway; GUI shows it; diagnosis stage 2 pings it; `route` is among the OS commands used.
2. **v1:** Gateway never detected or shown.
3. **Gap:** Missing feature; diagnosis stage 2 impossible.
4. **Change:** `get_default_gateway()` runs `route print` (Windows), `route -n get default` (macOS), `ip route` then `route -n` (Linux); `parse_gateway()` is separate so it is testable.
5. **Code:** `discovery.get_default_gateway`, `discovery.parse_gateway`; shown in the GUI info bar and the report.
6. **Test:** Header shows "Default gateway: <router IP>". Unplug the network -> "not detected". (Unit: `test_parse_gateway_all_formats`.)

### G-04 Discovery method: ping sweep + ARP cache, hostnames, ARP-only hosts
1. **Documentation:** Concurrent ping sweep; read the local ARP cache; devices in the ARP cache **may be included even if they do not answer ping**; reverse-DNS hostnames; maximum 1,022 hosts.
2. **v1:** scapy ARP *broadcast* (needs admin + Npcap) with a ping-sweep fallback; the ARP cache was never read; the local machine was force-added.
3. **Gap:** Different mechanism; ICMP-blocking hosts were only found when scapy worked.
4. **Change:** Sweep first (this also fills the ARP cache), then read the cache and union both sets. Each device records how it was found: `ICMP`, `ARP` or `ICMP+ARP`. Status is `Online` for ping replies and `ARP only` otherwise (an ARP cache entry can be stale, so it is not claimed as confirmed online).
5. **Code (`discovery.sweep_network`, abridged):**
```python
replied = {ip for ip, ok in zip(hosts, pool.map(probe, hosts)) if ok}
arp = {ip: mac for ip, mac in read_arp_table().items() if ip in host_set}   # read AFTER the sweep
found = sorted(replied | set(arp), key=ipaddress.IPv4Address)
```
6. **Test:** Scan a LAN containing a device that blocks ping (e.g. Windows with default firewall) -> it appears with "Detected via = ARP". Run without admin rights -> scan still works. (Unit: `test_sweep_includes_arp_only_devices`, `test_parse_arp_*`.)

### G-05 "Devices found? no: rescan"
1. **Documentation:** Figure 2 loops back to the scan when no devices are found.
2. **v1:** Single scan; empty result just displayed.
3. **Gap:** Workflow deviation.
4. **Change:** `discover()` rescans while the result is empty, **bounded** at `MAX_SCAN_ATTEMPTS = 3` (the figure's loop is unbounded; an unbounded loop would hang the GUI on a dead network).
5. **Code:** `discovery.discover`.
6. **Test:** Scan an empty range -> after three attempts the status bar says "No devices detected after rescanning." (Unit: `test_discover_rescans_when_empty`.)

### G-06 Vendor lookup (`oui.py`)
1. **Documentation:** Maps MAC prefixes to vendor names; shown in the device data.
2. **v1:** None.
3. **Gap:** Missing module and column.
4. **Change:** `lookup_vendor()` with an embedded table, plus detection of locally-administered (randomized) MACs used by phones.
5. **Code:** `netdoctor/oui.py`. **Limitation:** the table is a small starter set, not the IEEE registry; unknown prefixes show "Unknown" (see Section 3).
6. **Test:** A VMware/Raspberry Pi device shows its vendor; a phone with Private Wi-Fi Address shows "Private/randomized address". (Unit: `VendorTests`.)

### G-07 Connectivity test (`pinger.py`)
1. **Documentation:** OS `ping` through `subprocess`; `-n` (Windows) / `-c` (macOS, Linux) with platform timeouts; `parse_ping_output` separate from execution; Windows `<1 ms` recorded as 1 ms; **packet loss from requests sent vs. replies received, not summary text**; min, avg, max **and jitter** computed; ten requests.
2. **v1:** One subprocess *per packet* (slow; ten packets = ten process launches); default 4; no jitter.
3. **Gap:** Execution model, count, jitter.
4. **Change:** One command with the count flag; every reply line parsed; loss derived from `sent - received`. **Defect avoided:** a naive `time=...ms` regex also matches Windows' summary line (`Minimum = 1ms, Maximum = 2ms, Average = 1ms`), inventing three replies. The parser therefore only accepts lines that also contain `TTL=`, which excludes the summary and "Destination host unreachable" lines. It also accepts localized decimal commas.
5. **Code:**
```python
def parse_ping_output(text):
    times = []
    for line in text.splitlines():
        if not _TTL_RE.search(line):          # reply lines only
            continue
        m = _RTT_RE.search(line)              # "[=<] 12.3 ms"  ("<1ms" -> 1.0)
        if m:
            times.append(float(m.group(1).replace(",", ".")))
    return times
```
6. **Test:** Ping a LAN device -> 10 replies, loss 0 %. Unplug it mid-test -> loss > 0. (Unit: `PingerTests`, including Windows/Linux/macOS samples and the summary-line case.) **Not verified live on Windows/macOS** - see Section 5.

### G-08 Statistics (`stats.py`): selected devices, concurrency, terminology
1. **Documentation:** `measure_devices` tests **only the devices the user selected**, concurrently, returning hostname, IP, average, maximum latency and packet loss. A device with 100 % loss is **"unreachable"**.
2. **v1:** `ping_all` / single ping through a controller; pandas DataFrame; status wording "Offline".
3. **Gap:** Terminology ("Offline" vs "unreachable"), multi-select, pandas dependency.
4. **Change:** `measure_devices(devices)` with a thread pool; status is `Online`/`Unreachable`; `TABLE_HEADERS` is the single list of column names used by GUI, console and reports.
5. **Code:** `netdoctor/stats.py` (`DeviceStats.unreachable`, `high_loss`, `as_row`).
6. **Test:** Ctrl/Shift-select three devices -> "Test Selected Devices" -> three statistics rows. With none selected -> warning dialog. (Unit: `StatsTests`.)

### G-09 TCP port checks (`portscan.py`)
1. **Documentation:** `check_port` with a short timeout on ports **21, 22, 23, 80, 443, 3389**; a successful connection does not prove the service is secure; authorized use only.
2. **v1:** Optional helper on ports 21, 23, 445, 3389; never called by the GUI.
3. **Gap:** Wrong port list; not part of the workflow.
4. **Change:** Port checks run for every selected device as part of "Test Selected Devices", including devices that did not answer ping (the report says TCP evidence helps when ICMP is blocked). A one-time authorization notice appears before the first scan.
5. **Code:** `portscan.check_port / scan_ports / scan_devices`; `gui.AUTH_NOTICE`.
6. **Test:** Start a listener (`python -m http.server 80`) on a test host -> port `80/HTTP` appears in the report. (Unit: `PortScanTests`, using a real loopback socket.)

### G-10 Security recommendations (`security.py`) and thresholds
1. **Documentation:** 100 % loss = unreachable; **>= 20 % loss** = weak connectivity; **>= 100 ms average** = high latency; open **FTP/Telnet** flagged; devices not in the baseline marked unknown; general firewall, password, update reminders; messages are preliminary, not proof of compromise.
2. **v1:** Weak loss > 5 %, critical >= 25 %; high latency 150 ms, very high 300 ms; jitter rule; RDP/SMB flags; no unknown-device rule; "Critical/Warning/Info" levels.
3. **Gap:** Four thresholds wrong; two undocumented rules; one required rule missing.
4. **Change:** Thresholds moved to `config.py` with `[DOC]` tags. Removed the jitter rule, the "critical"/"very high" tiers and the RDP/SMB flags (not documented). Severity is `Warning` / `Info` only. Wording uses "may" and states that an open port does not mean compromise.
5. **Code (boundary behaviour):**
```python
if s.unreachable:            # loss >= 100
    ...
elif s.high_loss:            # 20 <= loss < 100
    ...
if s.avg_ms is not None and s.avg_ms >= config.HIGH_LATENCY_MS:   # >= 100
    ...
```
6. **Test:** Loss 19.9 % -> no alert; 20 % -> weak connectivity; 100 % -> unreachable only; 99.9 ms -> none; 100 ms -> high latency; ports 22/80/443/3389 open -> no alert; 21 or 23 open -> alert. (Unit: `SecurityTests`, all boundaries.)

### G-11 Trusted-device baseline (`baseline.py`)
1. **Documentation:** JSON file; devices compared **primarily by MAC**, IP only as fallback when MAC is unavailable; "Save trusted baseline" use case; unknown devices feed the recommendations.
2. **v1:** None.
3. **Gap:** Missing feature and use case.
4. **Change:** Atomic JSON write (temp file + rename); `find_unknown()`; corrupt file raises `BaselineError`, which the session logs and shows in the alert bar instead of crashing. GUI "Save Trusted Baseline" saves the selected devices, or (after a confirmation naming the count) all detected devices.
5. **Code:**
```python
trusted = (normalize_mac(d.mac) in trusted_macs) if d.mac else (d.ip in trusted_ips)
```
6. **Test:** Save baseline, change a device's DHCP address -> still Trusted. Connect a new device and rescan -> "UNKNOWN" row + alert bar entry. Corrupt `data/baseline.json` -> "baseline file unreadable" alert, no crash. (Unit: `BaselineTests`.)

### G-12 Network health score (`health.py`)
1. **Documentation:** 0-100 = reachability (<= 40, share of tested devices that respond) + packet loss (<= 30, reaches 0 at **30 % average loss**) + latency (<= 30, full at **<= 20 ms**, 0 at **200 ms**). Excellent 90-100, Good 75-89, Fair 60-74, Poor < 60. A project-defined indicator.
2. **v1:** A four-level "health" label with different cut-offs and no score.
3. **Gap:** Missing feature.
4. **Change:** `compute_health()` exactly as specified; GUI shows score, rating and the three component points; the report includes the "not an industry-standard rating" statement.
5. **Code:**
```python
reach = 40 * len(responding) / tested
loss  = 30 * (1 - min(avg_loss, 30) / 30)
lat   = 30 * max(0.0, min(1.0, 1 - (avg_latency - 20) / (200 - 20)))
score = int(round(reach + loss + lat))        # rating uses this integer
```
6. **Test:** 4 healthy devices -> 100 Excellent. 3 healthy + 1 unreachable -> 65 Fair (30 + 5 + 30). Latency 110 ms -> 15 latency points. 60 % loss -> 0 loss points. Boundaries 90/89/75/74/60/59. (Unit: `HealthTests`.) Hand-check one live result against the formula for your Chapter 4.

### G-13 Layer-by-layer diagnosis (`diagnostics.py`)
1. **Documentation:** Five checks in order - (1) usable IP configuration, (2) gateway answers ping, (3) an internet IP answers ping, (4) a domain resolves through DNS, (5) a TCP connection to an internet host succeeds. **Stops at the first failure** and reports that stage. Results do not prove a single layer is responsible. Runs independently of monitoring.
2. **v1:** None.
3. **Gap:** Missing feature and use case.
4. **Change:** Five `Check` objects run by `run_diagnosis()`; remaining stages are shown as *Skipped*; a check that raises is recorded as *Failed* (never crashes the wizard). Stage 5 reuses the address resolved in stage 4 so it tests TCP only. DNS runs under a timeout thread because `getaddrinfo` has none. Failure hints are worded as possible causes.
5. **Code:**
```python
for chk in checks:
    if stopped:
        res = CheckResult(chk.stage, chk.name, chk.layer, "Skipped")
    else:
        ok, detail = chk.func(ctx)
        res = CheckResult(chk.stage, chk.name, chk.layer, "Passed" if ok else "Failed", detail, ...)
        stopped = not ok
```
6. **Test:** Healthy network -> five "Passed". Unplug cable -> fails at stage 1 or 2, rest Skipped. Block the internet at the router -> stage 3. Set DNS to an invalid server -> stage 4. (Unit: `DiagnosticsTests`.) I verified stages 1-3 live; stages 4-5 only by mocks (sandbox has no internet).

### G-14 Report generator (`report.py`)
1. **Documentation:** Text **and** HTML. Contains date/time, detected devices, ping results, performance summary, **network health score, diagnostic outcome**, recommendations.
2. **v1:** PDF only; no health score or diagnostic outcome.
3. **Gap:** Wrong formats; two sections missing.
4. **Change:** One section list drives both formats, so they cannot drift apart. HTML escapes every value (a hostname such as `<script>` is rendered inert - tested) and highlights unreachable / high-loss / unknown rows as the GUI does. Local IP, range, gateway and device count are kept from the original brief.
5. **Code:** `report.build_text`, `report.build_html`, `report.save_reports`.
6. **Test:** Generate a report -> `reports/netdoctor_report_<stamp>.txt` and `.html` with 7 numbered sections. Open the HTML, Print -> Save as PDF. (Unit: `SessionAndReportTests`.)

### G-15 GUI (`gui.py`): terminology, widgets, threading
1. **Documentation:** Tkinter; shows local IP, network range, gateway, device list, statistics, diagnostic output, recommendations; **multi-select**; scanning/measuring in worker threads with results returned **through a queue**, widgets updated only by the main thread; unreachable / high-loss devices **highlighted**. Use-case names (Figure 3): Scan network devices, Ping selected devices, View network statistics, Run layer diagnosis, Save trusted baseline, Generate report, View security recommendations.
2. **v1:** CustomTkinter; single selection; callbacks via `after`; History tab; "Offline"; no highlight of high loss; dark-mode toggle.
3. **Gap:** Toolkit, selection, thread hand-off mechanism, terminology, missing views.
4. **Change:** Plain `tkinter/ttk`. Info bar (IP, range, gateway, health score). Buttons and tabs use the documented names. Workers put `progress`/`done` messages on a `queue.Queue`; `_poll_queue` (main thread) applies them. An alert bar summarizes unreachable, weak-connectivity, high-latency, risky-service and unknown-device counts. Selection is preserved across refreshes (found and fixed during GUI testing). Long recommendations are shown in full below the table. Buttons are disabled while a task runs.
5. **Code:** `netdoctor/gui.py`; screenshots in `docs/screenshots/`.
6. **Test:** Scan, select several, test: window stays responsive, progress bar moves, rows turn red/amber, alert bar updates, selection stays. Click any button during a run -> disabled.

### G-16 Persistence
1. **Documentation:** "The application stores the trusted-device baseline and generated reports" (Figure 1: `baseline.json`, report files).
2. **v1:** SQLite database of scans.
3. **Gap:** Undocumented persistence layer.
4. **Change:** Removed (C3). If you want scan history later, add it as a documented extension rather than silently.
5. **Code:** `database.py` and History tab deleted.
6. **Test:** After a run only `data/baseline.json`, `reports/*` and `logs/netdoctor.log` exist.

### G-17 Undocumented items kept in v2 (please add to the report or tell me to remove them)
| Item | Why it exists |
|---|---|
| `netdoctor/session.py` (`MonitoringSession`) | Table 2 has no orchestration module. Without it the GUI and console mode each re-implement Figure 2's sequence, breaking the report's own rule that both interfaces behave identically. ~120 lines; inline into `main.py`/`gui.py` if you prefer strict Table 2 fidelity. |
| `logs/netdoctor.log` (rotating) | Requested "improved logging"; configured in `main.py`. |
| Console flags `--diagnose`, `--prefix`, `--network`, `--devices`, `--save-baseline`, `--no-report`, `-v` | Console-mode convenience. Only `--cli` is documented; the report says diagnosis can run independently but names no flag for it. |

### G-18 Validation, error handling, logging (your request; not in the report)
| Area | Change |
|---|---|
| Command injection | Every IP is validated by `ipaddress.IPv4Address` before reaching `subprocess` (tested with `1.1.1.1; ls`). |
| Ping failures | Missing `ping` -> `PingError` with a clear message; whole-command timeout guard; partial output still parsed. |
| Range input | CIDR validated; oversized range rejected. |
| Baseline | Atomic write; corrupt file handled. |
| Worker threads | Exceptions are logged with a traceback and shown as a dialog (expected errors) or "see logs" (unexpected). |
| Logging | Rotating file log, warnings to stderr, `-v` for debug. |

### G-19 Automated tests
1. **Documentation:** 19 unit tests in `tests/test_netdoctor.py` covering ping parsing (Windows, Linux), loss/latency maths, subnets, ARP parsing, vendor lookup, health score, security rules, baseline handling, report sections.
2. **v1:** 19 pytest tests in `tests/test_core.py` testing different things.
3. **Gap:** Wrong file, framework and coverage.
4. **Change:** `tests/test_netdoctor.py` using `unittest` (stdlib). **49 tests**, all passing, covering every area the report lists plus macOS output, thresholds at exact boundaries, diagnosis stop-at-first-failure and HTML escaping.
5. **Code:** `tests/test_netdoctor.py`.
6. **Test:** `python -m unittest discover -s tests -t . -v`. **Update the report's "19" to 49** (or tell me to trim the suite - I would not).

---------------------------------------------------------------------------

## 3. Open decisions: the report is silent, so I chose a default (change in `config.py` unless noted)

| # | Topic | Choice made | Alternative |
|---|---|---|---|
| 1 | Diagnosis targets | Internet IP `8.8.8.8`; DNS name `example.com`; TCP `:443` on the resolved address | Any hosts you prefer; name them in the report |
| 2 | Health: average packet loss | Mean over **all** tested devices (literal reading) | Mean over responding devices only (avoids penalizing a dead host twice) |
| 3 | Health: average latency | Mean of per-device averages of responding devices; no replies -> 0 points | Pool all individual samples |
| 4 | Health: rating | Rounded integer score is banded | Band the unrounded value (89.6 -> Good instead of Excellent) |
| 5 | No baseline saved | Unknown-device check skipped, Info message shown | Treat every device as unknown (noisy) |
| 6 | What the baseline stores | Selected devices, or all after confirmation | Always all |
| 7 | Jitter | Mean absolute difference of consecutive replies | RFC 3550 smoothed jitter / standard deviation |
| 8 | Rescan bound | 3 attempts | Unlimited (as drawn in Figure 2) |
| 9 | Timeouts | Ping 2 s, sweep 1 s, TCP port 0.5 s, DNS/TCP diagnosis 3 s | - |
| 10 | Vendor table | ~14 well-known prefixes + randomized-MAC detection | Load the full IEEE OUI list |
| 11 | ARP-only status label | "ARP only" (not "Online") | "Online" |
| 12 | Severity levels | `Warning` / `Info` | Report defines none |
| 13 | IP fallback matching | A MAC-less device matches any baseline entry with the same IP | Only baseline entries that also lack a MAC |
| 14 | Port checks on unreachable devices | Yes (TCP can succeed when ICMP is blocked) | Skip unreachable devices |

---------------------------------------------------------------------------

## 4. Inconsistencies inside the report (fix the text, not the code)

1. **Figure 2 says "Run checks from Layer 1 upward"**, but there is no Layer 1 check and, by Table 3, the five stages map to Layers 3, 3, 3, 7, 4 - not ascending. v2 labels stages 1-5 and shows the Table 3 layer only as information.
2. **Objective 3 omits minimum latency** while Table 2 says `pinger.py` computes it.
3. **"19 unit tests"** is out of date after this change (49).
4. **Chapter 4 is referenced** ("should be presented separately in Chapter 4") but the file ends at Chapter 3. Objective 7 (Wireshark) can only be evidenced there; v2 sends ICMP echo and TCP SYN traffic you can capture with filters `icmp` and `tcp.port in {21 22 23 80 443 3389}`.
5. **Table 3 appears before Tables 1 and 2**, and Figure captions are duplicated ("Figure 1." / "Figure 2." appear twice).
6. **Figure 3** is headed "seven use cases" but captioned "nine use cases" (7 user-initiated + 2 included; both are right, but say so once).
7. **Citation fit:** NIST SP 800-82r3 is titled *Guide to Operational Technology (OT) Security*; it is a weak source for general LAN monitoring practice. Consider a more fitting reference.

---------------------------------------------------------------------------

## 5. What was verified and what was not

| Verified here (Linux sandbox, Python 3.12) | Not verified |
|---|---|
| 49 unit tests pass | Live behaviour on **Windows and macOS** (ping/arp/route parsing is tested against sample output only) |
| Console mode against real `ping`, `route`, `arp` | Discovery on a **real multi-device LAN** (sandbox has only a gateway and loopback) |
| Full GUI flow under a virtual display: scan, multi-select test, diagnosis, baseline, report, screenshots | Diagnosis stages 4-5 against the real internet (mocked only) |
| Diagnosis stops at stage 3 with later stages skipped | Wireshark capture comparison (Objective 7: manual) |
| Text and HTML reports generated and inspected | |

Run the console mode and the manual checklist on your own network before submitting; screenshots in `docs/screenshots/` come from a loopback test and show test data only.

---------------------------------------------------------------------------

## 6. Migration map v1 -> v2

| v1 (`netmon`) | v2 (`netdoctor`) | Status |
|---|---|---|
| `network_info.py` | `discovery.py` | Rewritten (G-02, G-03) |
| `scanner.py` | `discovery.py` | Replaced (G-04, G-05) |
| `pinger.py` | `pinger.py` | Rewritten (G-07) |
| `stats.py` (pandas) | `stats.py` | Rewritten, stdlib (G-08) |
| `security.py` | `security.py` | Thresholds/rules replaced (G-10) |
| `report.py` (reportlab) | `report.py` | Text + HTML (G-14) |
| `controller.py` | `session.py` | Slimmed and renamed (G-17) |
| `gui/app.py` (customtkinter) | `gui.py` (tkinter) | Rewritten (G-15) |
| `database.py`, History tab | - | Removed (G-16) |
| `cli.py` | `main.py --cli` | Merged (G-01) |
| `models.py` | dataclasses live in their owning modules | Removed |
| - | `portscan.py`, `health.py`, `diagnostics.py`, `baseline.py`, `oui.py` | New (G-06, G-09, G-11, G-12, G-13) |

The v1 zip is untouched, so nothing is lost.
