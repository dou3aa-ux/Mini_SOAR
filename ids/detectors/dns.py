from collections import defaultdict, deque


def detect_dns_bursts(events, query_threshold=20, window_seconds=10):
    """Flag sources sending many DNS queries within a short time."""
    queries_by_source = defaultdict(list)

    for event in events:
        query_name = event.get("dns_query") or event.get("dsn_query")

        if query_name:
            queries_by_source[event["source_ip"]].append(event)

    alerts = []

    for source_ip, queries in queries_by_source.items():
        queries.sort(key=lambda event: event["timestamp"])
        window = deque()

        for event in queries:
            timestamp = event["timestamp"]
            window.append(event)

            while (
                window
                and timestamp - window[0]["timestamp"] > window_seconds
            ):
                window.popleft()

            if len(window) >= query_threshold:
                alerts.append({
                    "type": "dns_query_burst",
                    "severity": "medium",
                    "source_ip": source_ip,
                    "query_count": len(window),
                    "window_seconds": window_seconds,
                    "description": (
                        f"{source_ip} sent {len(window)} DNS queries "
                        f"within {window_seconds} seconds."
                    ),
                })
                break  # One alert per source.

    return alerts