# 📡 Python Network Sniffer

A real-time network packet sniffer built with Python that captures, analyzes, and logs network traffic using raw sockets. The tool provides detailed insights into Ethernet, IP, TCP, UDP, and ICMP packets, along with domain resolution and packet export functionality.

---

## 🚀 Features

* Real-time packet capture
* Ethernet frame analysis
* IPv4 packet parsing
* TCP, UDP, and ICMP protocol inspection
* TCP flag decoding (SYN, ACK, FIN, RST, PSH, URG)
* DNS traffic detection
* Domain name resolution from IP addresses
* Packet timestamping
* Traffic statistics
* Save captured packets to text files
* Clean terminal-based interface

---

## 📋 Protocols Supported

| Protocol                  | Support |
| ------------------------- | ------- |
| Ethernet                  | ✅       |
| IPv4                      | ✅       |
| TCP                       | ✅       |
| UDP                       | ✅       |
| ICMP                      | ✅       |
| DNS Detection             | ✅       |
| HTTP/HTTPS Identification | ✅       |

---

## 🛠️ Requirements

* Python 3.x
* Linux Operating System
* Root/Sudo privileges

### Python Modules

The project uses only built-in Python libraries:

```python
socket
struct
datetime
signal
sys
os
time
```

No external dependencies are required.

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/nomi2k4/Sniffer.git
cd Sniffer
```

Run the sniffer:

```bash
sudo python3 sniffer.py
```

> Raw sockets require administrator/root privileges.

---

## 📊 Sample Output

```text
======================================================================
PACKET #42
Time: 2025-08-20 14:32:10.421
======================================================================
📡 MAC: aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66
🌐 IP:  192.168.1.10 → 142.250.190.78
⏱️ TTL: 64
🔌 Protocol: TCP
🔢 Ports: 54821 → 443
🌍 Website: google.com (HTTPS)
🔢 Seq/Ack: 123456 / 654321
🚩 Flags: SYN ACK
📦 Payload: 512 bytes
```

---

## 💾 Saving Captured Packets

Press:

```text
CTRL + C
```

The program will prompt:

```text
Save to file? (y/n)
```

If selected, all captured packet information will be exported to a text file for later analysis.

---

## 📂 Project Structure

```text
Sniffer/
│
├── sniffer.py
├── README.md
└── captured_packets.txt (generated)
```
