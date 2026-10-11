from ids.detectors.port_scan import detect_port_scans
from ids.detectors.dns import detect_dns_bursts
from ids.detectors.ssh_activity import detect_ssh_connection_bursts
from ids.detectors.beaconing import detect_beaconing

from config import (
    BEACON_MAX_JITTER_RATIO,
    BEACON_MIN_CONNECTIONS,
    DNS_QUERY_THRESHOLD,
    DNS_QUERY_WINDOW_SECONDS,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    SSH_ATTEMPT_THRESHOLD,
    SSH_WINDOW_SECONDS,
)


def generate_alerts(events):
    alerts = []

    alerts.extend(
        detect_port_scans(
            events,
            port_threshold=PORT_SCAN_THRESHOLD,
            window_seconds=PORT_SCAN_WINDOW_SECONDS,
        )
    )

    alerts.extend(
        detect_dns_bursts(
            events,
            query_threshold=DNS_QUERY_THRESHOLD,
            window_seconds=DNS_QUERY_WINDOW_SECONDS,
        )
    )

    alerts.extend(
        detect_ssh_connection_bursts(
            events,
            attempt_threshold=SSH_ATTEMPT_THRESHOLD,
            window_seconds=SSH_WINDOW_SECONDS,
        )
    )

    alerts.extend(
        detect_beaconing(
            events,
            min_connections=BEACON_MIN_CONNECTIONS,
            max_jitter_ratio=BEACON_MAX_JITTER_RATIO,
        )
    )

    return alerts