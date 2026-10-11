from collections import defaultdict
from statistics import pstdev


def detect_beaconing(
    events,
    min_connections=5,
    max_jitter_ratio=0.20,
    min_interval_seconds=1,
):
    """Flag repeated TCP SYN attempts with roughly regular timing."""
    connections_by_flow = defaultdict(list)

    for event in events:
        flags = event.get("tcp_flags") or ""

        if (
            event.get("protocol") == "TCP"
            and "S" in flags
            and "A" not in flags
        ):
            flow = (
                event["source_ip"],
                event["destination_ip"],
                event["destination_port"],
            )
            connections_by_flow[flow].append(event["timestamp"])

    alerts = []

    for (source_ip, destination_ip, destination_port), timestamps in (
        connections_by_flow.items()
    ):
        timestamps.sort()

        if len(timestamps) < min_connections:
            continue

        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        average_interval = sum(intervals) / len(intervals)

        if average_interval < min_interval_seconds:
            continue

        jitter_ratio = pstdev(intervals) / average_interval

        if jitter_ratio <= max_jitter_ratio:
            alerts.append({
                "type": "beaconing",
                "severity": "medium",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "connection_count": len(timestamps),
                "average_interval_seconds": round(average_interval, 2),
                "jitter_ratio": round(jitter_ratio, 3),
                "description": (
                    f"{source_ip} made repeated connections to "
                    f"{destination_ip}:{destination_port} at roughly "
                    f"{average_interval:.2f}-second intervals."
                ),
            })

    return alerts