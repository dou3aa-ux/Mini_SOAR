import ipaddress
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from config import ABUSEIPDB_API_KEY


API_URL = "https://api.abuseipdb.com/api/v2/check"


def enrich_ip(ip_address, api_key=None, max_age_days=90):
    """Look up a public IP address with AbuseIPDB."""
    try:
        parsed_ip = ipaddress.ip_address(ip_address)
    except (ValueError, TypeError):
        return {
            "status": "invalid_ip",
            "ip_address": str(ip_address),
        }

    # Avoid sending private, reserved, or documentation IPs to the service.
    if not parsed_ip.is_global:
        return {
            "status": "skipped",
            "ip_address": str(parsed_ip),
            "reason": "IP address is not globally routable.",
        }

    key = api_key or ABUSEIPDB_API_KEY
    if not key:
        return {
            "status": "not_configured",
            "ip_address": str(parsed_ip),
            "reason": "Add ABUSEIPDB_API_KEY to your local .env file.",
        }

    query = urlencode({
        "ipAddress": str(parsed_ip),
        "maxAgeInDays": max_age_days,
    })

    request = Request(
        f"{API_URL}?{query}",
        headers={
            "Key": key,
            "Accept": "application/json",
        },
    )

    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        return {
            "status": "error",
            "ip_address": str(parsed_ip),
            "reason": f"AbuseIPDB returned HTTP {error.code}.",
        }
    except (URLError, TimeoutError):
        return {
            "status": "error",
            "ip_address": str(parsed_ip),
            "reason": "Could not reach AbuseIPDB.",
        }
    except json.JSONDecodeError:
        return {
            "status": "error",
            "ip_address": str(parsed_ip),
            "reason": "AbuseIPDB returned invalid JSON.",
        }

    data = payload.get("data", {})

    return {
        "status": "ok",
        "ip_address": data.get("ipAddress", str(parsed_ip)),
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
    }
def enrich_alerts(alerts):
    cache = {}

    for alert in alerts:
        source_ip = alert.get("source_ip")

        if not source_ip:
            alert["enrichment"] = {
                "status": "skipped",
                "reason": "Alert has no source IP.",
            }
            continue

        # Look up each source IP only once per PCAP run.
        if source_ip not in cache:
            cache[source_ip] = enrich_ip(source_ip)

        alert["enrichment"] = cache[source_ip]

    return alerts