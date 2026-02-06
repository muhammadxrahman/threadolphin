# Threadolphin: a C++ Packet Sniffer (Mini-Wireshark)

A low-level network packet capture tool written in C++ using `libpcap`. This project manually decodes the network stack (Ethernet -> IP -> TCP) and extracts application payloads from raw binary traffic.

## Features
* **Device Scanning:** Enumerates all available network interfaces.
* **Promiscuous Mode:** Captures traffic not specifically addressed to the host.
* **Protocol Parsing:**
    * **Ethernet:** MAC Address decoding.
    * **IPv4:** Header length calculation and address resolution.
    * **TCP:** Port mapping and Flag detection (SYN/ACK/FIN).
* **Deep Packet Inspection:** Extracts and sanitizes ASCII payloads (e.g., HTTP headers).

## Prerequisites

### macOS (most likely already installed)
```bash
brew install libpcap
```

### Linux (Debian/Ubuntu)
```bash
sudo apt-get install libpcap-dev
```

### Windows
1. Install Npcap (Ensure "Install in WinPcap API-compatible Mode" is checked).
2. Download the Npcap SDK.