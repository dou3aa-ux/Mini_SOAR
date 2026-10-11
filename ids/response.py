def plan_response(alert):
    """Describe a possible response without executing it."""
    source_ip = alert.get("source_ip")
    severity = (alert.get("severity") or "").lower()

    if not source_ip:
        action = "manual_review"
        message = "No source IP is available; review the alert manually."
    elif severity in {"high", "critical"}:
        action = "would_block_source_ip"
        message = f"Dry run: would consider blocking {source_ip}."
    else:
        action = "would_review_source_ip"
        message = f"Dry run: would review activity from {source_ip}."

    return {
        "mode": "dry_run",
        "executed": False,
        "alert_type": alert.get("type", "unknown"),
        "source_ip": source_ip,
        "action": action,
        "message": message,
    }