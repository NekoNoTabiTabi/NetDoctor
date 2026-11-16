"""Unit tests (stdlib unittest). Network access is mocked except for the two
loopback socket tests, so the suite runs offline.

    python -m unittest discover -s tests -t . -v
"""

import json
import socket
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from netdoctor import (baseline, config, diagnostics, discovery, health, oui,
                       pinger, portscan, report, security, stats)
from netdoctor.discovery import Device
from netdoctor.session import MonitoringSession
from netdoctor.stats import DeviceStats

# ------------------------------------------------------------ sample outputs
WINDOWS_PING = """\
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=3ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Request timed out.
Reply from 192.168.1.20: Destination host unreachable.

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 3ms, Average = 1ms
"""
LINUX_PING = """\
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=0.045 ms

--- 192.168.1.1 ping statistics ---
4 packets transmitted, 2 received, 50% packet loss, time 3010ms
rtt min/avg/max/mdev = 0.045/0.637/1.230/0.592 ms
"""
MAC_PING = """\
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.345 ms
round-trip min/avg/max/stddev = 12.345/12.345/12.345/0.000 ms
"""
WINDOWS_ARP = """\
Interface: 192.168.1.10 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.20          AA-BB-CC-DD-EE-14     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
LINUX_ARP = """\
? (192.168.1.1) at aa:bb:cc:dd:ee:01 [ether] on eth0
? (192.168.1.99) at <incomplete> on eth0
"""
MAC_ARP = "? (192.168.1.5) at a:b:c:d:e:f on en0 ifscope [ethernet]\n"
IP_NEIGH = ("192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
            "192.168.1.9 dev eth0  FAILED\n"
            "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 router STALE\n")


def mk_stats(ip="10.0.0.1", loss=0.0, avg=10.0, sent=10, name="host"):
    """DeviceStats with the given loss % and average latency."""
    received = round(sent * (100 - loss) / 100)
    return DeviceStats(hostname=name, ip=ip, sent=sent, received=received, loss_pct=loss,
                       avg_ms=None if received == 0 else avg,
                       max_ms=None if received == 0 else avg + 5,
                       min_ms=None if received == 0 else max(avg - 5, 0), jitter_ms=1.0)


class PingerTests(unittest.TestCase):
    def test_parse_windows_sub_ms_is_one_and_summary_ignored(self):
        self.assertEqual(pinger.parse_ping_output(WINDOWS_PING), [3.0, 1.0])

    def test_parse_linux_and_macos(self):
        self.assertEqual(pinger.parse_ping_output(LINUX_PING), [1.23, 0.045])
        self.assertEqual(pinger.parse_ping_output(MAC_PING), [12.345])

    def test_parse_decimal_comma(self):
        self.assertEqual(pinger.parse_ping_output("Antwort: time=0,5 ms TTL=64"), [0.5])

    def test_command_per_platform(self):
        self.assertEqual(pinger.build_ping_command("1.1.1.1", 10, 2, "Windows"),
                         ["ping", "-n", "10", "-w", "2000", "1.1.1.1"])
        self.assertEqual(pinger.build_ping_command("1.1.1.1", 10, 2, "Linux"),
                         ["ping", "-c", "10", "-W", "2", "1.1.1.1"])
        self.assertEqual(pinger.build_ping_command("1.1.1.1", 10, 2, "Darwin"),
                         ["ping", "-c", "10", "-W", "2000", "1.1.1.1"])

    def test_loss_from_sent_and_received_not_summary(self):
        proc = mock.Mock(stdout=LINUX_PING.replace("50% packet loss", "0% packet loss"))
        with mock.patch.object(pinger.subprocess, "run", return_value=proc):
            r = pinger.ping_host("192.168.1.1", count=4)
        self.assertEqual((r.sent, r.received, r.loss_pct), (4, 2, 50.0))
        self.assertEqual((r.min_ms, r.max_ms, r.avg_ms), (0.04, 1.23, 0.64))

    def test_jitter(self):
        r = pinger.PingResult("1.1.1.1", sent=3, received=3, rtts_ms=[10, 14, 12])
        self.assertEqual(r.jitter_ms, 3.0)
        self.assertIsNone(pinger.PingResult("1.1.1.1", sent=1, received=1, rtts_ms=[5]).jitter_ms)

    def test_default_count_is_ten(self):
        self.assertEqual(config.PING_COUNT, 10)

    def test_input_validation_blocks_injection(self):
        for bad in ("1.1.1.1; ls", "example.com", "", "1.2.3", "999.1.1.1"):
            with self.assertRaises(pinger.PingError):
                pinger.validate_ipv4(bad)
        with self.assertRaises(pinger.PingError):
            pinger.ping_host("1.1.1.1", count=0)

    def test_missing_ping_utility(self):
        with mock.patch.object(pinger.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(pinger.PingError):
                pinger.ping_host("1.1.1.1", count=1)


class DiscoveryTests(unittest.TestCase):
    def test_default_prefix_is_24(self):
        self.assertEqual(str(discovery.get_network("192.168.1.57")), "192.168.1.0/24")
        self.assertEqual(str(discovery.get_network("10.0.5.9", 25)), "10.0.5.0/25")

    def test_host_limit_1022(self):
        self.assertEqual(discovery.get_network("10.0.0.5", 22).num_addresses - 2, 1022)
        with self.assertRaises(discovery.DiscoveryError):
            discovery.get_network("10.0.0.5", 21)
        with self.assertRaises(discovery.DiscoveryError):
            discovery.parse_network("10.0.0.0/8")
        with self.assertRaises(discovery.DiscoveryError):
            discovery.parse_network("not a network")

    def test_parse_arp_windows_filters_broadcast_and_multicast(self):
        self.assertEqual(discovery.parse_arp_output(WINDOWS_ARP),
                         {"192.168.1.1": "aa:bb:cc:dd:ee:01", "192.168.1.20": "aa:bb:cc:dd:ee:14"})

    def test_parse_arp_linux_skips_incomplete(self):
        self.assertEqual(discovery.parse_arp_output(LINUX_ARP),
                         {"192.168.1.1": "aa:bb:cc:dd:ee:01"})

    def test_parse_arp_macos_pads_octets(self):
        self.assertEqual(discovery.parse_arp_output(MAC_ARP),
                         {"192.168.1.5": "0a:0b:0c:0d:0e:0f"})

    def test_parse_ip_neigh(self):
        self.assertEqual(discovery.parse_arp_output(IP_NEIGH),
                         {"192.168.1.1": "aa:bb:cc:dd:ee:01"})

    def test_parse_gateway_all_formats(self):
        self.assertEqual(discovery.parse_gateway("default via 192.168.1.1 dev eth0"), "192.168.1.1")
        self.assertEqual(discovery.parse_gateway(
            "Destination Gateway Genmask\n0.0.0.0         10.0.0.1        0.0.0.0   UG 0 0 0 eth0"), "10.0.0.1")
        self.assertEqual(discovery.parse_gateway("   gateway: 172.16.0.1\n  interface: en0"), "172.16.0.1")
        self.assertEqual(discovery.parse_gateway(
            "          0.0.0.0          0.0.0.0      192.168.0.1   192.168.0.5     25"), "192.168.0.1")
        self.assertIsNone(discovery.parse_gateway("nothing here"))

    def test_sweep_includes_arp_only_devices(self):
        net = discovery.parse_network("192.168.1.0/29")
        replies = {"192.168.1.1"}

        def fake_ping(ip, count=1, timeout_s=1.0, hostname="Unknown"):
            return pinger.PingResult(ip, sent=1, received=1 if ip in replies else 0,
                                     rtts_ms=[1.0] if ip in replies else [])

        arp = {"192.168.1.1": "00:50:56:aa:bb:cc", "192.168.1.3": "aa:bb:cc:dd:ee:03",
               "192.168.1.200": "aa:bb:cc:dd:ee:c8"}          # last one is outside the subnet
        with mock.patch.object(discovery, "ping_host", fake_ping), \
             mock.patch.object(discovery, "read_arp_table", return_value=arp), \
             mock.patch.object(discovery, "resolve_hostname", return_value="h"):
            devices = discovery.sweep_network(net)
        by_ip = {d.ip: d for d in devices}
        self.assertEqual(sorted(by_ip), ["192.168.1.1", "192.168.1.3"])
        self.assertEqual(by_ip["192.168.1.1"].via, "ICMP+ARP")
        self.assertEqual(by_ip["192.168.1.1"].vendor, "VMware")
        self.assertEqual(by_ip["192.168.1.3"].via, "ARP")
        self.assertEqual(by_ip["192.168.1.3"].status, "ARP only")

    def test_discover_rescans_when_empty(self):
        net = discovery.parse_network("192.168.1.0/30")
        dev = Device("192.168.1.1")
        with mock.patch.object(discovery, "sweep_network", side_effect=[[], [], [dev]]) as sw:
            self.assertEqual(discovery.discover(net), [dev])
        self.assertEqual(sw.call_count, 3)
        with mock.patch.object(discovery, "sweep_network", return_value=[]) as sw:
            self.assertEqual(discovery.discover(net, max_attempts=2), [])
        self.assertEqual(sw.call_count, 2)


class VendorTests(unittest.TestCase):
    def test_lookup(self):
        self.assertEqual(oui.lookup_vendor("00-50-56-AA-BB-CC"), "VMware")
        self.assertEqual(oui.lookup_vendor("b8:27:eb:00:00:01"), "Raspberry Pi Foundation")
        self.assertEqual(oui.lookup_vendor("02:11:22:33:44:55"), "Private/randomized address")
        self.assertEqual(oui.lookup_vendor("00:11:22:33:44:55"), "Unknown")
        self.assertEqual(oui.lookup_vendor(None), "Unknown")
        self.assertEqual(oui.lookup_vendor("garbage"), "Unknown")


class StatsTests(unittest.TestCase):
    def test_row_and_status(self):
        ok, dead = mk_stats(avg=12.5), mk_stats("10.0.0.2", loss=100)
        self.assertEqual(ok.as_row(), ("host", "10.0.0.1", 12.5, 17.5, 7.5, 0.0, "Online"))
        self.assertEqual(dead.as_row()[2:], ("N/A", "N/A", "N/A", 100.0, "Unreachable"))
        self.assertEqual(len(stats.TABLE_HEADERS), len(ok.as_row()))

    def test_measure_selected_devices_keeps_order(self):
        devs = [Device("10.0.0.2", "b"), Device("10.0.0.1", "a")]

        def fake(ip, count, hostname):
            return pinger.PingResult(ip, hostname, sent=count, received=count, rtts_ms=[1.0] * count)

        with mock.patch.object(stats, "ping_host", side_effect=fake):
            result = stats.measure_devices(devs)
        self.assertEqual([r.ip for r in result], ["10.0.0.2", "10.0.0.1"])
        self.assertTrue(all(r.sent == 10 for r in result))
        self.assertEqual(stats.measure_devices([]), [])


class PortScanTests(unittest.TestCase):
    def test_open_and_closed_ports(self):
        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            self.assertTrue(portscan.check_port("127.0.0.1", port))
            self.assertEqual(portscan.scan_ports("127.0.0.1", [port]), [port])
        self.assertFalse(portscan.check_port("127.0.0.1", port))      # now closed

    def test_configured_ports_match_report(self):
        self.assertEqual(sorted(config.PORTS), [21, 22, 23, 80, 443, 3389])


class SecurityTests(unittest.TestCase):
    def cats(self, recs):
        return {(r.category, r.target) for r in recs}

    def test_unreachable_is_100_percent_only(self):
        c = self.cats(security.analyze([mk_stats("1.1.1.1", loss=100)], unknown_devices=[]))
        self.assertIn(("Unreachable host", "1.1.1.1"), c)
        self.assertNotIn(("Weak connectivity", "1.1.1.1"), c)

    def test_weak_connectivity_threshold_is_20(self):
        below = security.analyze([mk_stats(loss=10, sent=10)], unknown_devices=[])
        at = security.analyze([mk_stats(loss=20, sent=10)], unknown_devices=[])
        self.assertNotIn("Weak connectivity", {r.category for r in below})
        self.assertIn("Weak connectivity", {r.category for r in at})
        self.assertNotIn("Weak connectivity",
                         {r.category for r in security.analyze([mk_stats(loss=19.9)], unknown_devices=[])})

    def test_high_latency_threshold_is_100(self):
        self.assertNotIn("High latency", {r.category for r in
                         security.analyze([mk_stats(avg=99.9)], unknown_devices=[])})
        self.assertIn("High latency", {r.category for r in
                      security.analyze([mk_stats(avg=100.0)], unknown_devices=[])})

    def test_only_ftp_and_telnet_flagged(self):
        recs = security.analyze([], {"10.0.0.1": [21, 22, 23, 80, 443, 3389]}, [])
        flagged = [r.message for r in recs if r.category == "Potentially risky service"]
        self.assertEqual(len(flagged), 2)
        self.assertTrue(any("port 21" in m for m in flagged) and any("port 23" in m for m in flagged))
        self.assertEqual([r for r in security.analyze([], {"10.0.0.1": [22, 80, 443, 3389]}, [])
                          if r.category == "Potentially risky service"], [])

    def test_unknown_devices_and_missing_baseline(self):
        d = Device("10.0.0.9", "x", "aa:bb:cc:dd:ee:09")
        recs = security.analyze([], None, [d])
        self.assertIn(("Unknown device", "10.0.0.9"), self.cats(recs))
        self.assertIn("Trusted-device baseline", {r.category for r in security.analyze([], None, None)})
        self.assertNotIn("Unknown device", {r.category for r in security.analyze([], None, [])})

    def test_general_reminders_and_ordering(self):
        recs = security.analyze([mk_stats(loss=100)], unknown_devices=[])
        self.assertTrue({"Firewall", "Password", "Updates"} <= {r.category for r in recs})
        severities = [r.severity for r in recs]
        self.assertEqual(severities, sorted(severities, key=lambda s: s != "Warning"))


class HealthTests(unittest.TestCase):
    def test_perfect_network(self):
        h = health.compute_health([mk_stats(f"10.0.0.{i}", avg=10) for i in range(1, 5)])
        self.assertEqual((h.score, h.rating), (100, "Excellent"))

    def test_components(self):
        # 1 of 4 unreachable: reach 30; avg loss 25 -> 5; latency 10 ms -> 30 = 65
        s = [mk_stats("1", avg=10), mk_stats("2", avg=10), mk_stats("3", avg=10),
             mk_stats("4", loss=100)]
        h = health.compute_health(s)
        self.assertEqual((h.reachability_pts, h.loss_pts, h.latency_pts), (30.0, 5.0, 30.0))
        self.assertEqual((h.score, h.rating), (65, "Fair"))

    def test_latency_linear_between_20_and_200(self):
        pts = lambda ms: health.compute_health([mk_stats(avg=ms)]).latency_pts
        self.assertEqual(pts(20), 30.0)
        self.assertEqual(pts(5), 30.0)
        self.assertEqual(pts(110), 15.0)
        self.assertEqual(pts(200), 0.0)
        self.assertEqual(pts(500), 0.0)

    def test_loss_component_zero_at_30_percent(self):
        loss_pts = lambda p: health.compute_health([mk_stats(loss=p)]).loss_pts
        self.assertEqual(loss_pts(0), 30.0)
        self.assertEqual(loss_pts(15), 15.0)
        self.assertEqual(loss_pts(30), 0.0)
        self.assertEqual(loss_pts(60), 0.0)

    def test_rating_bands(self):
        got = [health.rating_for(n) for n in (100, 90, 89, 75, 74, 60, 59, 0)]
        self.assertEqual(got, ["Excellent", "Excellent", "Good", "Good", "Fair", "Fair", "Poor", "Poor"])

    def test_all_unreachable_and_empty(self):
        h = health.compute_health([mk_stats(loss=100), mk_stats("2", loss=100)])
        self.assertEqual((h.score, h.rating, h.avg_latency_ms), (0, "Poor", None))
        self.assertIsNone(health.compute_health([]))


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "baseline.json"

    def test_roundtrip_and_missing(self):
        self.assertIsNone(baseline.load_baseline(self.path))
        n = baseline.save_baseline([Device("10.0.0.1", "r", "AA-BB-CC-DD-EE-01")], self.path)
        self.assertEqual(n, 1)
        self.assertEqual(baseline.load_baseline(self.path)[0]["mac"], "aa:bb:cc:dd:ee:01")

    def test_match_by_mac_even_if_ip_changed(self):
        baseline.save_baseline([Device("10.0.0.1", "r", "aa:bb:cc:dd:ee:01")], self.path)
        base = baseline.load_baseline(self.path)
        moved = Device("10.0.0.77", "r", "AA-BB-CC-DD-EE-01")
        stranger = Device("10.0.0.1", "x", "aa:bb:cc:dd:ee:99")      # same IP, other MAC
        self.assertEqual(baseline.find_unknown([moved, stranger], base), [stranger])

    def test_ip_fallback_when_mac_unavailable(self):
        baseline.save_baseline([Device("10.0.0.1", "r", None)], self.path)
        base = baseline.load_baseline(self.path)
        self.assertEqual(baseline.find_unknown([Device("10.0.0.1")], base), [])
        self.assertEqual(len(baseline.find_unknown([Device("10.0.0.2")], base)), 1)

    def test_invalid_file_and_empty_save(self):
        self.path.write_text("{not json")
        with self.assertRaises(baseline.BaselineError):
            baseline.load_baseline(self.path)
        self.path.write_text(json.dumps({"devices": "nope"}))
        with self.assertRaises(baseline.BaselineError):
            baseline.load_baseline(self.path)
        with self.assertRaises(baseline.BaselineError):
            baseline.save_baseline([], self.path)


class DiagnosticsTests(unittest.TestCase):
    @staticmethod
    def chk(stage, ok, calls):
        def fn(ctx):
            calls.append(stage)
            return ok, f"detail {stage}"
        return diagnostics.Check(stage, f"check {stage}", "L", fn, f"hint {stage}")

    def test_stops_at_first_failure(self):
        calls = []
        res = diagnostics.run_diagnosis([self.chk(1, True, calls), self.chk(2, False, calls),
                                         self.chk(3, True, calls)])
        self.assertEqual(calls, [1, 2])                                 # stage 3 never ran
        self.assertEqual([r.status for r in res.results], ["Passed", "Failed", "Skipped"])
        self.assertEqual(res.failed.stage, 2)
        self.assertIn("Stage 2 failed", res.summary)
        self.assertIn("hint 2", res.summary)

    def test_all_pass(self):
        res = diagnostics.run_diagnosis([self.chk(i, True, []) for i in (1, 2)])
        self.assertTrue(res.passed)
        self.assertIn("passed", res.summary)

    def test_exception_counts_as_failure(self):
        def boom(ctx):
            raise RuntimeError("x")
        with self.assertLogs("netdoctor.diagnostics", level="ERROR"):
            res = diagnostics.run_diagnosis([diagnostics.Check(1, "c", "L", boom, "h")])
        self.assertEqual(res.results[0].status, "Failed")

    def test_five_default_stages_in_documented_order(self):
        self.assertEqual([c.stage for c in diagnostics.DEFAULT_CHECKS], [1, 2, 3, 4, 5])
        names = " ".join(c.name for c in diagnostics.DEFAULT_CHECKS).lower()
        for word in ("ip configuration", "gateway", "internet", "dns", "tcp"):
            self.assertIn(word, names)

    def test_link_local_address_fails_stage_1(self):
        with mock.patch.object(diagnostics, "get_local_ip", return_value="169.254.3.4"):
            ok, _ = diagnostics.check_ip_configuration({})
        self.assertFalse(ok)

    def test_missing_gateway_fails_stage_2(self):
        with mock.patch.object(diagnostics, "get_default_gateway", return_value=None):
            self.assertFalse(diagnostics.check_gateway({})[0])


class SessionAndReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.s = MonitoringSession(baseline_path=self.dir / "baseline.json")
        self.s.local_ip, self.s.network, self.s.gateway = "10.0.0.5", "10.0.0.0/24", "10.0.0.1"
        self.s.scanned_at = datetime(2026, 11, 16, 9, 30)
        self.s.devices = [Device("10.0.0.1", "router", "aa:bb:cc:dd:ee:01", "Unknown", "ICMP+ARP"),
                          Device("10.0.0.7", "<script>x</script>", None, "Unknown", "ICMP")]

    def fake_measure(self, devices, count=10, progress=None):
        return [mk_stats("10.0.0.1", avg=3, name="router"), mk_stats("10.0.0.7", loss=100, name="odd")]

    def test_measure_requires_selection(self):
        with self.assertRaises(ValueError):
            self.s.measure([])

    def test_workflow_and_report_contents(self):
        with mock.patch("netdoctor.session.measure_devices", self.fake_measure), \
             mock.patch("netdoctor.session.scan_devices",
                        return_value={"10.0.0.1": [80, 23], "10.0.0.7": []}):
            self.s.measure(["10.0.0.1", "10.0.0.7"])
        # reach 40*1/2=20; avg loss 50% -> 0; latency 3 ms -> 30  => 50 (Poor)
        self.assertEqual((self.s.health.score, self.s.health.rating), (50, "Poor"))
        self.assertIsNone(self.s.unknown_devices)                      # no baseline yet
        self.assertEqual(self.s.save_baseline(["10.0.0.1"]), 1)
        self.assertEqual([d.ip for d in self.s.unknown_devices], ["10.0.0.7"])

        self.s.diagnosis = diagnostics.run_diagnosis([DiagnosticsTests.chk(1, True, [])])
        text = report.build_text(self.s)
        for needle in ("2026-11-16 09:30:00", "10.0.0.5", "10.0.0.0/24", "Devices detected      : 2",
                       "Average Latency (ms)", "Network Health Score", "Diagnostic Outcome",
                       "Security Recommendations", "Potentially risky service", "Unreachable",
                       "UNKNOWN", "23/Telnet"):
            self.assertIn(needle, text)

        html_doc = report.build_html(self.s)
        self.assertNotIn("<script>x</script>", html_doc)               # escaped
        self.assertIn("&lt;script&gt;", html_doc)
        self.assertIn("class='bad'", html_doc)

        txt, htm = self.s.generate_report(self.dir / "out")
        self.assertTrue(txt.exists() and htm.exists())
        self.assertTrue(htm.read_text(encoding="utf-8").startswith("<!DOCTYPE html>"))

    def test_report_without_data_is_rejected(self):
        empty = MonitoringSession(baseline_path=self.dir / "b.json")
        empty.scanned_at = datetime.now()
        with self.assertRaises(report.ReportError):
            empty.generate_report(self.dir)

    def test_corrupt_baseline_is_reported_not_fatal(self):
        (self.dir / "baseline.json").write_text("{broken")
        with self.assertLogs("netdoctor.session", level="ERROR"):
            self.s.refresh_analysis()
        self.assertIsNone(self.s.unknown_devices)
        self.assertIn("invalid", self.s.baseline_error)


if __name__ == "__main__":
    unittest.main()
