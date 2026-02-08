# Network Checksum Validator

This project validates checksums of network packets using the Scapy library.

It performs checksum verification for:
- IPv4
- TCP
- UDP
- ICMP

## Objective

To extract packet header fields from a PCAP file and recalculate checksums programmatically using Scapy, then compare them with the original checksum values.

## Tools Used

- Python 3
- Scapy
- Wireshark
- GitHub

## Files in Repository

- checksum_validation.py → Main Python script
- lab6capture.pcap → Contains IP, TCP, UDP, TLS packets
- icmp_capture.pcap → Contains ICMP packets
- README.md → Project documentation

## How It Works

For each packet in the PCAP file:

1. The original checksum field is extracted.
2. The packet is rebuilt using Scapy.
3. Scapy automatically recalculates the checksum.
4. The recalculated value is compared with the original.
5. The result is printed as VALID or INVALID.

## How to Run

Install Scapy:

pip3 install scapy

Run the script:

python3 checksum_validation.py <pcap_file>

Example:

python3 checksum_validation.py lab6capture.pcap

python3 checksum_validation.py icmp_capture.pcap

## Notes

- Ethernet FCS cannot be validated in software because it is handled by NIC hardware.
- TLS does not use a traditional checksum; it uses cryptographic integrity mechanisms.
- ICMP does not use a pseudo-header.
- TCP and UDP include pseudo-header in checksum calculation.

## Author

Maanya Agrawal
