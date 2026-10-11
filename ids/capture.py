import sys
from scapy.utils import PcapReader

from ids.parser import parse_packet
from ids.alerts import generate_alerts
from ids.database import save_alerts
from ids.enrichment import enrich_alerts
from ids.notifications import send_discord_alert
from ids.response import plan_response


def analyse_pcap(pcap_path):
    events = []

    with PcapReader(pcap_path) as packets:
        for packet in packets:
            event = parse_packet(packet)

            if event is not None:
                events.append(event)
                print(event)

    print(f"\nFinished: {len(events)} IP packets read.")

    alerts = generate_alerts(events)
    alerts = enrich_alerts(alerts)

    for alert in alerts:
        alert["response_plan"] = plan_response(alert)

    if alerts:
        print("\nAlerts:")
        for alert in alerts:
            print(alert)

            notification = send_discord_alert(alert)  # dry-run by default
            print("\nDiscord notification preview:")
            print(notification["message"])
    else:
        print("\nNo alerts detected.")

    saved_ids = save_alerts(alerts)
    print(f"\nSaved {len(saved_ids)} alert(s) to data/ids.db.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m ids.capture <pcap_file>")
        sys.exit(1)

    analyse_pcap(sys.argv[1])