from collections import Counter, defaultdict, deque


def detect_ssh_connection_bursts(events, attempt_threshold=5, window_seconds=60):
    """Flag repeated TCP connection attempts to SSH (port 22)."""
    attempts_by_pair = defaultdict(list)

    for event in events:
        flags = event.get("tcp_flags") or ""

        if (
            event.get("protocol") == "TCP"
            and event.get("destination_port") == 22
            and "S" in flags
            and "A" not in flags
        ):
            key = (event["source_ip"], event["destination_ip"])
            attempts_by_pair[key].append(event)

    alerts = []

    for (source_ip, destination_ip), attempts in attempts_by_pair.items():
        attempts.sort(key=lambda event: event["timestamp"])

        window = deque()
        source_port_counts = Counter()

        for event in attempts:
            timestamp = event["timestamp"]
            source_port = event["source_port"]

            window.append(event)
            source_port_counts[source_port] += 1

            while (
                window
                and timestamp - window[0]["timestamp"] > window_seconds
            ):
                old_event = window.popleft()
                old_source_port = old_event["source_port"]
                source_port_counts[old_source_port] -= 1

                if source_port_counts[old_source_port] == 0:
                    del source_port_counts[old_source_port]

            if len(source_port_counts) >= attempt_threshold:
                alerts.append({
                    "type": "ssh_connection_burst",
                    "severity": "medium",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "unique_attempts": len(source_port_counts),
                    "window_seconds": window_seconds,
                    "description": (
                        f"{source_ip} made at least "
                        f"{len(source_port_counts)} distinct connection "
                        f"attempts to SSH on {destination_ip} within "
                        f"{window_seconds} seconds."
                    ),
                })
                break  # One alert per source/destination pair.

    return alerts