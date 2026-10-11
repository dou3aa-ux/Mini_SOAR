import unittest

from ids.detectors.beaconing import detect_beaconing


def make_event(timestamp, destination_port=443, tcp_flags="S"):
    return {
        "timestamp": timestamp,
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": destination_port,
        "tcp_flags": tcp_flags,
        "dns_query": None,
    }


class TestBeaconingDetector(unittest.TestCase):

    def test_detects_regular_connection_intervals(self):
        # Five attempts, each 10 seconds apart.
        events = [
            make_event(timestamp=i * 10)
            for i in range(5)
        ]

        alerts = detect_beaconing(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "beaconing")
        self.assertEqual(alerts[0]["connection_count"], 5)
        self.assertEqual(alerts[0]["average_interval_seconds"], 10)

    def test_does_not_alert_for_irregular_intervals(self):
        # Intervals are 5, 10, 15, and 20 seconds.
        events = [
            make_event(timestamp=t)
            for t in [0, 5, 15, 30, 50]
        ]

        alerts = detect_beaconing(events)

        self.assertEqual(alerts, [])

    def test_does_not_alert_with_too_few_connections(self):
        events = [
            make_event(timestamp=i * 10)
            for i in range(4)
        ]

        alerts = detect_beaconing(events)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()