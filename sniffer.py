import socket
import struct
import time
from datetime import datetime
import signal
import sys
import os

class FullSniffer:
    def __init__(self):
        self.packet_count = 0
        self.packets_data = []
        self.running = True
        self.output_file = None
        
        # Setup Ctrl+C handler
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C to save and exit"""
        print(f"\n\n{'='*70}")
        print(f"[!] Capture stopped. Total packets captured: {self.packet_count}")
        
        # Ask for filename
        if self.packet_count > 0:
            save = input("\n[*] Save to file? (y/n): ").lower()
            if save == 'y':
                filename = input("[*] Enter filename (without extension): ")
                filename = f"{filename}.txt"
                self.save_to_file(filename)
                print(f"[+] Packets saved to: {filename}")
        
        print(f"{'='*70}")
        sys.exit(0)
    
    def parse_ethernet(self, data):
        """Parse Ethernet header"""
        dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
        return {
            'src_mac': src_mac.hex(':'),
            'dest_mac': dest_mac.hex(':'),
            'protocol': proto,
            'payload': data[14:]
        }
    
    def parse_ip(self, data):
        """Parse IP header"""
        version_ihl = data[0]
        ihl = (version_ihl & 0xF) * 4
        ttl, proto, src_ip, dest_ip = struct.unpack('!8xBB2x4s4s', data[:20])
        return {
            'ttl': ttl,
            'protocol': proto,
            'src_ip': socket.inet_ntoa(src_ip),
            'dest_ip': socket.inet_ntoa(dest_ip),
            'ihl': ihl,
            'payload': data[ihl:]
        }
    
    def get_domain_name(self, ip_address):
        """Try to get domain name from IP address"""
        try:
            # Skip private/local IPs
            if ip_address.startswith(('127.', '192.168.', '10.', '172.')):
                return ip_address
            domain = socket.gethostbyaddr(ip_address)
            return domain[0]
        except:
            return ip_address
    
    def parse_tcp(self, data):
        """Parse TCP header"""
        src_port, dest_port, seq, ack, offset_reserved = struct.unpack('!HHLLH', data[:14])
        offset = (offset_reserved >> 12) * 4
        flags = offset_reserved & 0x1FF
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'seq': seq,
            'ack': ack,
            'flags': flags,
            'payload_size': len(data[offset:])
        }
    
    def parse_udp(self, data):
        """Parse UDP header"""
        src_port, dest_port, length = struct.unpack('!HHH', data[:6])
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'length': length,
            'payload_size': len(data[8:])
        }
    
    def parse_icmp(self, data):
        """Parse ICMP header"""
        icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
        return {
            'type': icmp_type,
            'code': code,
            'payload_size': len(data[4:])
        }
    
    def get_flag_string(self, flags):
        """Convert TCP flags to readable format"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return ' '.join(flag_names) if flag_names else 'None'
    
    def get_website_info(self, ip, port):
        """Get website/domain information"""
        domain = self.get_domain_name(ip)
        
        # Common ports and their services
        services = {
            80: "HTTP",
            443: "HTTPS",
            53: "DNS",
            22: "SSH",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            3306: "MySQL",
            5432: "PostgreSQL"
        }
        
        service = services.get(port, "Unknown")
        
        if domain != ip:
            return f"{domain} ({service})"
        else:
            return f"{ip} ({service})"
    
    def save_to_file(self, filename):
        """Save all captured packets to a text file"""
        with open(filename, 'w') as f:
            f.write("="*80 + "\n")
            f.write("PACKET CAPTURE LOG\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Packets: {self.packet_count}\n")
            f.write("="*80 + "\n\n")
            
            for packet in self.packets_data:
                f.write(packet + "\n\n")
    
    def main(self):
        # Create raw socket
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        banner = r"""

   ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
   ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
   ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
   ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
   ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
   ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

"""

        print(banner)
        print("\n" + "="*70)
        print(" NETWORK SNIFFER - Complete Packet Analyzer")
        print("="*70)
        print("[*] Capturing all network traffic...")
        print("[*] Press Ctrl+C to stop and save")
        print("="*70 + "\n")
        
        try:
            while self.running:
                raw_data, addr = conn.recvfrom(65536)
                self.packet_count += 1
                
                # Get timestamp
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                # Parse Ethernet
                eth = self.parse_ethernet(raw_data)
                
                output_lines = []
                output_lines.append(f"{'='*70}")
                output_lines.append(f"PACKET #{self.packet_count}")
                output_lines.append(f"Time: {timestamp}")
                output_lines.append(f"{'='*70}")
                
                # Check if it's IP packet
                if eth['protocol'] == 0x0800:
                    ip = self.parse_ip(eth['payload'])
                    
                    output_lines.append(f"📡 MAC: {eth['src_mac']} → {eth['dest_mac']}")
                    output_lines.append(f"🌐 IP:  {ip['src_ip']} → {ip['dest_ip']}")
                    output_lines.append(f"⏱️  TTL: {ip['ttl']}")
                    
                    # Parse based on protocol
                    if ip['protocol'] == 6:  # TCP
                        tcp = self.parse_tcp(ip['payload'])
                        output_lines.append(f"🔌 Protocol: TCP")
                        output_lines.append(f"🔢 Ports: {tcp['src_port']} → {tcp['dest_port']}")
                        
                        # Show website/domain
                        if tcp['dest_port'] in [80, 443, 8080, 8443]:
                            website = self.get_website_info(ip['dest_ip'], tcp['dest_port'])
                            output_lines.append(f"🌍 Website: {website}")
                        elif tcp['src_port'] in [80, 443, 8080, 8443]:
                            website = self.get_website_info(ip['src_ip'], tcp['src_port'])
                            output_lines.append(f"🌍 Website: {website}")
                        
                        output_lines.append(f"🔢 Seq/Ack: {tcp['seq']} / {tcp['ack']}")
                        output_lines.append(f"🚩 Flags: {self.get_flag_string(tcp['flags'])}")
                        output_lines.append(f"📦 Payload: {tcp['payload_size']} bytes")
                        
                    elif ip['protocol'] == 17:  # UDP
                        udp = self.parse_udp(ip['payload'])
                        output_lines.append(f"📡 Protocol: UDP")
                        output_lines.append(f"🔢 Ports: {udp['src_port']} → {udp['dest_port']}")
                        
                        # Show DNS queries
                        if udp['dest_port'] == 53 or udp['src_port'] == 53:
                            output_lines.append(f"🌍 DNS Query/Response")
                        
                        output_lines.append(f"📦 Payload: {udp['payload_size']} bytes")
                        
                    elif ip['protocol'] == 1:  # ICMP
                        icmp = self.parse_icmp(ip['payload'])
                        output_lines.append(f"📡 Protocol: ICMP")
                        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable", 11: "Time Exceeded"}
                        output_lines.append(f"🔢 Type/Code: {icmp['type']}/{icmp['code']} ({icmp_types.get(icmp['type'], 'Unknown')})")
                        output_lines.append(f"📦 Payload: {icmp['payload_size']} bytes")
                        
                    else:
                        output_lines.append(f"📡 Protocol: Other ({ip['protocol']})")
                        
                else:
                    output_lines.append(f"📡 Non-IP packet (EtherType: 0x{eth['protocol']:04x})")
                
                # Print to screen
                for line in output_lines:
                    print(line)
                print()
                
                # Store for saving later
                self.packets_data.append("\n".join(output_lines))
                
        except Exception as e:
            print(f"Error: {e}")
            self.signal_handler(None, None)

if __name__ == "__main__":
    sniffer = FullSniffer()
    sniffer.main()
