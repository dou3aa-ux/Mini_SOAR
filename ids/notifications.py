import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from config import DISCORD_WEBHOOK_URL


def format_alert_message(alert):
    """Format an IDS alert as a short Discord message."""
    lines = [
        "🚨 Mini IDS alert",
        f"Type: {alert.get('type', 'unknown')}",
        f"Severity: {alert.get('severity', 'unknown').upper()}",
        f"Source: {alert.get('source_ip') or 'unknown'}",
        f"Destination: {alert.get('destination_ip') or 'unknown'}",
        alert.get("description", "No description"),
    ]

    enrichment = alert.get("enrichment", {})
    score = enrichment.get("abuse_confidence_score")
    if score is not None:
        lines.append(f"AbuseIPDB confidence score: {score}%")

    # Discord limits message content to 2,000 characters.
    return "\n".join(lines)[:2000]


def send_discord_alert(alert, webhook_url=None, dry_run=True):
    """Preview an alert, or send it to Discord when dry_run=False."""
    message = format_alert_message(alert)

    if dry_run:
        return {"status": "dry_run", "message": message}

    target_url = webhook_url or DISCORD_WEBHOOK_URL
    if not target_url:
        return {
            "status": "not_configured",
            "reason": "Set DISCORD_WEBHOOK_URL in your local .env file.",
        }

    parsed_url = urlparse(target_url)
    if parsed_url.scheme != "https" or parsed_url.hostname != "discord.com":
        return {
            "status": "error",
            "reason": "The webhook must use an https://discord.com URL.",
        }

    payload = {
        "content": message,
        "allowed_mentions": {"parse": []},
    }

    request = Request(
        target_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=10) as response:
            return {"status": "sent", "http_status": response.status}
    except HTTPError as error:
        return {
            "status": "error",
            "reason": f"Discord returned HTTP {error.code}.",
        }
    except (URLError, TimeoutError):
        return {"status": "error", "reason": "Could not reach Discord."}