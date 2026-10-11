from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap


project_root = Path(__file__).resolve().parent
data_dir = project_root / "data"
data_dir.mkdir(parents=True, exist_ok=True)

pcap_path = data_dir / "sample.pcap"
packets = []

print("Creating fictional test packets...")

for destination_port in range(20, 38):
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(
            sport=50000 + destination_port,
            dport=destination_port,
            flags="S",
        )
    )
    packets.append(packet)

dns_packet = (
    Ether()
    / IP(src="192.0.2.10", dst="198.51.100.53")
    / UDP(sport=53000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="demo.test"))
)
packets.append(dns_packet)

wrpcap(str(pcap_path), packets)

print(f"Created {len(packets)} packets in: {pcap_path}")