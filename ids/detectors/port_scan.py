from collections import Counter, defaultdict, deque


def detect_port_scans(events, port_threshold=15, window_seconds=10):
    grouped = defaultdict(list)

    for event in events:
        flags = event.get("tcp_flags") or ""

        if (
            event.get("protocol") == "TCP"
            and "S" in flags
            and "A" not in flags
        ):
            key = (event["source_ip"], event["destination_ip"])
            grouped[key].append(event)

    alerts = []

    for (source_ip, destination_ip), packets in grouped.items():
        packets.sort(key=lambda packet: packet["timestamp"])

        window = deque()
        port_counts = Counter()

        for packet in packets:
            timestamp = packet["timestamp"]
            port = packet["destination_port"]

            window.append(packet)
            port_counts[port] += 1

            # Keep only packets inside the configured time window.
            while window and timestamp - window[0]["timestamp"] > window_seconds:
                old_packet = window.popleft()
                old_port = old_packet["destination_port"]
                port_counts[old_port] -= 1
                if port_counts[old_port] == 0:
                    del port_counts[old_port]

            if len(port_counts) >= port_threshold:
                alerts.append({
                    "type": "port_scan",
                    "severity": "high",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "unique_ports": len(port_counts),
                    "ports": sorted(port_counts),
                    "window_seconds": window_seconds,
                    "description": (
                        f"{source_ip} probed {len(port_counts)} ports "
                        f"on {destination_ip} within "
                        f"{window_seconds} seconds."
                    ),
                })
                break  # One alert for this source/destination pair.

    return alerts