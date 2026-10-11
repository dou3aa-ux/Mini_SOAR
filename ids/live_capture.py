import argparse
from pathlib import Path

from scapy.all import sniff, wrpcap

from ids.capture import analyse_pcap


def capture_live(interface, duration, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Capturing IP traffic for {duration} seconds...")
    print(f"Interface: {interface or 'Scapy default'}")

    packets = sniff(
        iface=interface or None,
        filter="ip",
        timeout=duration,
        store=True,
        quiet=True,
    )

    if not packets:
        print("No IP packets captured. Check the interface and try again.")
        return

    wrpcap(str(output_path), packets)
    print(f"Captured {len(packets)} packets to {output_path}")

    analyse_pcap(str(output_path))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture and analyse live IP traffic.")
    parser.add_argument("--interface", help="Interface name from show_interfaces().")
    parser.add_argument("--duration", type=int, default=60, help="Capture length in seconds.")
    parser.add_argument(
        "--output",
        default="data/live_capture.pcap",
        help="Where to save the capture.",
    )
    args = parser.parse_args()

    if args.duration <= 0:
        parser.error("--duration must be greater than zero")

    capture_live(args.interface, args.duration, args.output)