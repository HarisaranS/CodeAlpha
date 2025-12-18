# Network Packet Analyzer Using Python

## Overview
The **Network Packet Analyzer** is a professional Python-based command-line application designed to capture and analyze live network traffic.  
It uses the **Scapy** library to inspect packets in real time and extract meaningful information such as IP addresses, transport-layer protocols, port numbers, and packet payloads.

---

## Objectives
- Capture live network traffic using Python  
- Analyze packet structure and protocol behavior  
- Identify TCP, UDP, and ICMP packets  
- Log packet details in a structured and professional format  
- Save captured packets for offline forensic analysis  

---

## Technologies Used
- **Programming Language:** Python 3.8+
- **Library:** Scapy
- **Standard Modules:** argparse, logging, datetime
- **Operating System:** Linux / Windows
- **Packet Format:** PCAP (Wireshark compatible)

> Administrator or root privileges are required for packet capturing.

---

## Project Structure

 - network_packet_analyzer/
 - │
 - ├── sniffer.py
 - ├── README.md
 - ├── sniffer.log
 - └── captures/
 - └── traffic_YYYYMMDD_HHMMSS.pcap

---

## Installation

### Install Python
Verify Python installation:
```bash
  python --version
```
### Install Required Library
```bash
 pip install scapy
```
### Run Packet Analyzer
```bash
  sudo python sniffer.py
```
### Capture a Specific Number of Packets
```bash
  sudo python sniffer.py --count 50
```
### Capture Packets by Protocol
```bash
  sudo python sniffer.py --protocol tcp
```
### Capture and Save Packets to PCAP
```bash
  sudo python sniffer.py --count 100 --protocol udp --save
```

---

## Packet Analysis Details
### Each captured packet is analyzed to extract:
- Source IP address
- Destination IP address
- Transport protocol (TCP, UDP, ICMP)
- Source and destination ports (for TCP/UDP)
- Packet payload (if present)
- Captured packets can be further analyzed using network forensic tools such as Wireshark.

---

## PCAP Export
### When the --save option is enabled:
- Captured packets are saved in the captures/ directory
- Files are timestamped for easy identification
- PCAP files are fully compatible with Wireshark and tcpdump

---

## Ethical and Legal Disclaimer
### This tool is intended strictly for educational and authorized use only.

- Unauthorized network packet capturing is illegal and unethical.
- Always obtain explicit permission before analyzing any network.

---

## Learning Outcomes
- Understanding of network packet flow
- Hands-on experience with TCP, UDP, and ICMP protocols
- Practical exposure to packet sniffing tools
- Improved knowledge of cybersecurity fundamentals

---

## Limitations
- Encrypted traffic (HTTPS) cannot be decrypted
- Requires administrator/root privileges
- Designed for learning and demonstration purposes

---

## Future Enhancements
- HTTP and DNS packet parsing
- Detection of suspicious traffic patterns
- Export packet details to CSV or JSON
- Graphical User Interface (GUI)

---

## Conclusion
- The Network Packet Analyzer Using Python successfully demonstrates real-time network packet capturing and analysis.
- The project aligns with academic and industry expectations and provides a strong foundation for advanced networking and cybersecurity projects.

---

## Declaration
- This project was developed solely for academic and educational purposes.
- All packet captures were performed in a controlled and authorized environment.

---

