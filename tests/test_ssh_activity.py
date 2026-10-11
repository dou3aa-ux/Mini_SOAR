import unittest

from ids.detectors.ssh_activity import detect_ssh_connection_bursts


def make_ssh_event(timestamp, source_port, destination_port=22, tcp_flags="S"):
    return {
        "timestamp": timestamp,
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "protocol": "TCP",
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_flags": tcp_flags,
        "dns_query": None,
    }


class TestSshActivityDetector(unittest.TestCase):

    def test_detects_repeated_ssh_connection_attempts(self):
        events = [
            make_ssh_event(timestamp=i, source_port=50000 + i)
            for i in range(5)
        ]

        alerts = detect_ssh_connection_bursts(
            events,
            attempt_threshold=5,
            window_seconds=60,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "ssh_connection_burst")
        self.assertEqual(alerts[0]["unique_attempts"], 5)

    def test_does_not_alert_below_threshold(self):
        events = [
            make_ssh_event(timestamp=i, source_port=50000 + i)
            for i in range(4)
        ]

        alerts = detect_ssh_connection_bursts(
            events,
            attempt_threshold=5,
            window_seconds=60,
        )

        self.assertEqual(alerts, [])

    def test_ignores_syn_ack_responses(self):
        events = [
            make_ssh_event(
                timestamp=i,
                source_port=50000 + i,
                tcp_flags="SA",
            )
            for i in range(5)
        ]

        alerts = detect_ssh_connection_bursts(
            events,
            attempt_threshold=5,
            window_seconds=60,
        )

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()