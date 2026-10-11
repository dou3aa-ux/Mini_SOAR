import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from ids.alerts import generate_alerts
from ids.database import get_recent_alerts, save_alerts
from ids.notifications import send_discord_alert
from ids.response import plan_response


class TestAlertPipeline(unittest.TestCase):

    def test_generate_alerts_combines_detector_results(self):
        expected = [
            {"type": "port_scan"},
            {"type": "dns_query_burst"},
            {"type": "ssh_connection_burst"},
            {"type": "beaconing"},
        ]

        with ExitStack() as stack:
            detectors = [
                stack.enter_context(patch(
                    "ids.alerts.detect_port_scans",
                    return_value=[expected[0]],
                )),
                stack.enter_context(patch(
                    "ids.alerts.detect_dns_bursts",
                    return_value=[expected[1]],
                )),
                stack.enter_context(patch(
                    "ids.alerts.detect_ssh_connection_bursts",
                    return_value=[expected[2]],
                )),
                stack.enter_context(patch(
                    "ids.alerts.detect_beaconing",
                    return_value=[expected[3]],
                )),
            ]

            result = generate_alerts([])

        self.assertEqual(result, expected)
        for detector in detectors:
            detector.assert_called_once()

    def test_response_plan_is_dry_run(self):
        plan = plan_response({
            "type": "port_scan",
            "severity": "high",
            "source_ip": "192.0.2.10",
        })

        self.assertEqual(plan["mode"], "dry_run")
        self.assertFalse(plan["executed"])

    def test_discord_notification_defaults_to_preview(self):
        result = send_discord_alert({
            "type": "port_scan",
            "severity": "high",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "description": "Sample alert",
        })

        self.assertEqual(result["status"], "dry_run")
        self.assertIn("Sample alert", result["message"])

    def test_alert_and_metadata_round_trip_through_database(self):
        alert = {
            "type": "port_scan",
            "severity": "high",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "description": "Sample alert",
            "response_plan": {"mode": "dry_run", "executed": False},
        }

        with tempfile.TemporaryDirectory() as temporary_folder:
            test_db = Path(temporary_folder) / "test_ids.db"

            saved_ids = save_alerts([alert], db_path=test_db)
            loaded_alerts = get_recent_alerts(db_path=test_db)

        self.assertEqual(len(saved_ids), 1)
        self.assertEqual(len(loaded_alerts), 1)
        self.assertEqual(
            loaded_alerts[0]["details"]["response_plan"]["mode"],
            "dry_run",
        )


if __name__ == "__main__":
    unittest.main()