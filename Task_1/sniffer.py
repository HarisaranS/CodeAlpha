import argparse
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap


# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("sniffer.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


# Packet Analysis Function
def analyze_packet(packet):
    """
    Analyze individual packets and extract useful information.
    """

    if IP not in packet:
        return

    ip = packet[IP]
    protocol = "OTHER"

    if TCP in packet:
        protocol = "TCP"
        transport = packet[TCP]
    elif UDP in packet:
        protocol = "UDP"
        transport = packet[UDP]
    elif ICMP in packet:
        protocol = "ICMP"
        transport = None

    logger.info(
        f"Src: {ip.src} | Dst: {ip.dst} | "
        f"Proto: {protocol}"
    )

    if transport:
        logger.info(
            f"Ports: {transport.sport} → {transport.dport}"
        )

    if packet.haslayer(Raw):
        payload = packet[Raw].load
        logger.debug(f"Payload (truncated): {payload[:64]}")


# Packet Capture Engine
def start_sniffing(packet_count, protocol_filter, save_pcap):
    """
    Start capturing packets based on user input.
    """

    logger.info("Starting packet capture...")
    logger.info(f"Packet Count: {packet_count}")
    logger.info(f"Protocol Filter: {protocol_filter or 'ALL'}")

    bpf_filter = protocol_filter if protocol_filter else None

    packets = sniff(
        filter=bpf_filter,
        prn=analyze_packet,
        count=packet_count,
        store=True
    )

    if save_pcap:
        filename = f"captures/traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(filename, packets)
        logger.info(f"Packets saved to {filename}")

    logger.info("Packet capture completed successfully.")


# CLI Argument Parser
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Professional Network Packet Analyzer"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of packets to capture"
    )

    parser.add_argument(
        "--protocol",
        type=str,
        choices=["tcp", "udp", "icmp"],
        help="Filter packets by protocol"
    )

    parser.add_argument(
        "--save",
        action="store_true",
        help="Save captured packets to PCAP file"
    )

    return parser.parse_args()


# Main Entry Point
def main():
    args = parse_arguments()
    start_sniffing(
        packet_count=args.count,
        protocol_filter=args.protocol,
        save_pcap=args.save
    )


if __name__ == "__main__":
    main()
