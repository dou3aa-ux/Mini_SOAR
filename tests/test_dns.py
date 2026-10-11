import unittest

from ids.detectors.dns import detect_dns_bursts


def make_dns_event(timestamp, query_name="example.test"):
    return {
        "timestamp": timestamp,
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.53",
        "protocol": "UDP",
        "source_port": 53000,
        "destination_port": 53,
        "tcp_flags": None,
        "dns_query": query_name,
    }


class TestDnsBurstDetector(unittest.TestCase):

    def test_detects_many_queries_within_window(self):
        events = [
            make_dns_event(timestamp=i * 0.1)
            for i in range(20)
        ]

        alerts = detect_dns_bursts(
            events,
            query_threshold=20,
            window_seconds=10,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "dns_query_burst")
        self.assertEqual(alerts[0]["query_count"], 20)

    def test_does_not_alert_below_threshold(self):
        events = [
            make_dns_event(timestamp=i * 0.1)
            for i in range(19)
        ]

        alerts = detect_dns_bursts(
            events,
            query_threshold=20,
            window_seconds=10,
        )

        self.assertEqual(alerts, [])

    def test_old_queries_expire_from_window(self):
        events = [
            make_dns_event(timestamp=0),
            make_dns_event(timestamp=5),
            make_dns_event(timestamp=10),
        ]

        alerts = detect_dns_bursts(
            events,
            query_threshold=3,
            window_seconds=6,
        )

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()