from scapy.all import *
import sys


def validate_packet(pkt, index):
    print(f"\nPacket {index}")

    # Rebuild packet to force checksum recalculation
    rebuilt_pkt = pkt.__class__(bytes(pkt))

    # IP Checksum Validation
    if IP in pkt:
        original_ip = pkt[IP].chksum
        recalculated_ip = rebuilt_pkt[IP].chksum

        print("IP Checksum:")
        print(f"  Original     : {hex(original_ip)}")
        print(f"  Recalculated : {hex(recalculated_ip)}")
        print(f"  Status       : {'VALID' if original_ip == recalculated_ip else 'INVALID'}")

    # TCP Checksum Validation
    if TCP in pkt:
        original_tcp = pkt[TCP].chksum
        recalculated_tcp = rebuilt_pkt[TCP].chksum

        print("\nTCP Checksum:")
        print(f"  Original     : {hex(original_tcp)}")
        print(f"  Recalculated : {hex(recalculated_tcp)}")
        print(f"  Status       : {'VALID' if original_tcp == recalculated_tcp else 'INVALID'}")

    # UDP Checksum Validation
    if UDP in pkt:
        original_udp = pkt[UDP].chksum
        recalculated_udp = rebuilt_pkt[UDP].chksum

        print("\nUDP Checksum:")
        print(f"  Original     : {hex(original_udp)}")
        print(f"  Recalculated : {hex(recalculated_udp)}")
        print(f"  Status       : {'VALID' if original_udp == recalculated_udp else 'INVALID'}")

    # ICMP Checksum Validation
    if ICMP in pkt:
        original_icmp = pkt[ICMP].chksum
        recalculated_icmp = rebuilt_pkt[ICMP].chksum

        print("\nICMP Checksum:")
        print(f"  Original     : {hex(original_icmp)}")
        print(f"  Recalculated : {hex(recalculated_icmp)}")
        print(f"  Status       : {'VALID' if original_icmp == recalculated_icmp else 'INVALID'}")


# Main Execution

if len(sys.argv) != 2:
    print("Usage: python3 checksum_validation.py <pcap_file>")
    sys.exit(1)

pcap_file = sys.argv[1]

print(f"\nReading PCAP file: {pcap_file}")
packets = rdpcap(pcap_file)

print(f"Total Packets Found: {len(packets)}")

for i, packet in enumerate(packets, start=1):
    validate_packet(packet, i)

