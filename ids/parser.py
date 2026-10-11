from scapy.all import DNSQR, IP, TCP,UDP

def parse_packet(pkt):
    if IP not in pkt:
        return None

    event={"timestamp":float(pkt.time),"source_ip":pkt[IP].src,"destination_ip":pkt[IP].dst,"protocol":"IP","source_port":None,"destination_port":None,"tcp_flags":None,"dsn_query":None,}
    if TCP in pkt:
        event["protocol"]="TCP"
        event["source_port"]=pkt[TCP].sport
        event["destination_port"]=pkt[TCP].dport
        event["tcp_flags"]=str(pkt[TCP].flags)

    elif UDP in pkt:
        event["protocol"]="UDP"
        event["source_port"]=pkt[UDP].sport
        event["destination_port"]=pkt[UDP].dport
    if DNSQR in pkt:
        event["dsn_query"]=(pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip("."))

    return event