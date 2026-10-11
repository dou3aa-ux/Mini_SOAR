import unittest

from ids.detectors.port_scan import detect_port_scans


def make_tcp_event(timestamp, destination_port):
    return {
        "timestamp": timestamp,
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": destination_port,
        "tcp_flags": "S",
        "dsn_query": None,
    }


class TestPortScanDetector(unittest.TestCase):

    def test_detects_many_unique_ports(self):
        events = [
            make_tcp_event(timestamp=i * 0.1, destination_port=20 + i)
            for i in range(15)
        ]

        alerts = detect_port_scans(
            events,
            port_threshold=15,
            window_seconds=10,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "port_scan")
        self.assertEqual(alerts[0]["unique_ports"], 15)

    def test_does_not_alert_below_threshold(self):
        events = [
            make_tcp_event(timestamp=i * 0.1, destination_port=20 + i)
            for i in range(14)
        ]

        alerts = detect_port_scans(
            events,
            port_threshold=15,
            window_seconds=10,
        )

        self.assertEqual(alerts, [])

    def test_repeated_probes_to_one_port_do_not_count_as_many_ports(self):
        events = [
            make_tcp_event(timestamp=i * 0.1, destination_port=22)
            for i in range(20)
        ]

        alerts = detect_port_scans(
            events,
            port_threshold=15,
            window_seconds=10,
        )

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()