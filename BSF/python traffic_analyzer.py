#!/usr/bin/env python3
"""
Network Traffic Analysis Tool (Pure Python - No External Libs)
Usage: python traffic_analyzer.py [-f <pcap_file>] [-o <output.json>] [--csv] [--html]
If no -f provided, generates a dummy PCAP for testing.
Parses PCAP manually, extracts metrics, detects anomalies, generates report.
"""

import argparse
import json
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime
import struct
import base64
import random  # For dummy generation

# PCAP Constants (from libpcap format)
PCAP_MAGIC = 0xa1b2c3d4  # Little-endian
PCAP_HEADER_SIZE = 24
PCAP_PACKET_HEADER_SIZE = 16
ETH_HEADER_SIZE = 14
IP_HEADER_MIN_SIZE = 20
TCP_HEADER_MIN_SIZE = 20
UDP_HEADER_SIZE = 8

DUMMY_PCAP = 'dummy.pcap'

def parse_arguments():
    parser = argparse.ArgumentParser(description="Analyze network traffic from PCAP files (pure Python).")
    parser.add_argument('-f', '--file', help="Path to .pcap file (optional; generates dummy if omitted)")
    parser.add_argument('-o', '--output', default='report.json', help="Output file (JSON default)")
    parser.add_argument('--csv', action='store_true', help="Also output CSV metrics (requires pandas)")
    parser.add_argument('--html', action='store_true', help="Also output HTML report")
    parser.add_argument('--no-dummy', action='store_true', help="Skip dummy generation if no file provided")
    return parser.parse_args()

def generate_dummy_pcap(filename=DUMMY_PCAP, num_packets=50):
    """Generate a simple dummy PCAP with fake IPv4/TCP traffic for testing."""
    print(f"Generating dummy PCAP '{filename}' with {num_packets} packets...")
    with open(filename, 'wb') as f:
        # Global header
        global_header = struct.pack('<IHHIIII', PCAP_MAGIC, 2, 4, 0, 0, 65535, 1)  # Ethernet link type
        f.write(global_header)
        
        ts_base = datetime.now().timestamp()
        for i in range(num_packets):
            # Fake Ethernet + IP + TCP payload (simplified, minimal headers)
            # Ethernet: dst/src MAC (fake), proto=0x0800 (IPv4)
            eth_header = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x00\x08'  # 14 bytes
            # IP: version=4, ihl=5, proto=6 (TCP), src/dst IPs (fake)
            src_ip_bytes = struct.pack('!BBBB', 192, 168, 1, random.randint(1, 100))
            dst_ip_bytes = struct.pack('!BBBB', 8, 8, 8, 8)  # Google DNS
            ip_header = b'\x45\x00\x00\x28\x12\x34\x40\x00\x40\x06\x00\x00' + src_ip_bytes + dst_ip_bytes  # 20 bytes
            # TCP: src/dst ports (80 HTTP), fake flags/seq
            tcp_header = struct.pack('!HHLLBBHHH', random.randint(50000, 60000), 80, random.randint(1, 1000000), 0, 5<<4, 2, 0, 0, 0)  # 20 bytes
            # Fake payload (e.g., 'GET / HTTP/1.1\r\nAuthorization: Basic ' + base64)
            payload = b'GET / HTTP/1.1\r\nAuthorization: Basic ' + base64.b64encode(b'user:pass123') + b'\r\n\r\n'
            packet_data = eth_header + ip_header + tcp_header + payload
            
            # Packet header: ts_sec, ts_usec, incl_len, orig_len
            ts_sec = int(ts_base + i * 0.1)  # 0.1s intervals
            ts_usec = int((ts_base + i * 0.1 - ts_sec) * 1000000)
            pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(packet_data), len(packet_data))
            f.write(pkt_header + packet_data)
    
    print(f"Dummy PCAP generated: {num_packets} packets (includes fake HTTP Basic Auth for testing).")
    return filename

class PurePcapReader:
    """Minimal pure-Python PCAP parser using struct."""
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.packets = []  # List of {'ts': timestamp, 'len': length, 'data': raw_bytes}
    
    def load(self):
        """Read global header and packets."""
        try:
            with open(self.file_path, 'rb') as f:
                # Global header (24 bytes)
                header = f.read(PCAP_HEADER_SIZE)
                if len(header) < PCAP_HEADER_SIZE:
                    raise ValueError("File too small for PCAP header")
                
                magic, major, minor, tz, sigfigs, snaplen, linktype = struct.unpack('<IHHIIII', header)
                if magic != PCAP_MAGIC:
                    raise ValueError(f"Unsupported PCAP format (magic: 0x{magic:08x})")
                
                print(f"PCAP loaded: Version {major}.{minor}, Link type: {linktype}, Snaplen: {snaplen}")
                
                # Read packets
                packet_count = 0
                while True:
                    pkt_header = f.read(PCAP_PACKET_HEADER_SIZE)
                    if len(pkt_header) < PCAP_PACKET_HEADER_SIZE:
                        break
                    
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_header)
                    ts = ts_sec + (ts_usec / 1000000.0)
                    
                    raw_data = f.read(incl_len)
                    if len(raw_data) < incl_len:
                        break
                    
                    self.packets.append({
                        'ts': ts,
                        'len': incl_len,
                        'data': raw_data
                    })
                    packet_count += 1
                
                print(f"Loaded {packet_count} packets from {self.file_path}")
                return self.packets
                
        except Exception as e:
            print(f"Error loading PCAP: {e}", file=sys.stderr)
            sys.exit(1)

def parse_ethernet(raw_data):
    """Parse Ethernet header: dst/src MAC, protocol."""
    if len(raw_data) < ETH_HEADER_SIZE:
        return None
    eth_header = raw_data[:ETH_HEADER_SIZE]
    dst_mac, src_mac, proto = struct.unpack('!6s6sH', eth_header)
    if proto != 0x0800:  # IPv4 only
        return None
    return raw_data[ETH_HEADER_SIZE:]

def parse_ip(ip_data):
    """Parse IP header: src/dst IP, protocol, header length."""
    if len(ip_data) < IP_HEADER_MIN_SIZE:
        return None
    version_ihl = ip_data[0]
    ihl = (version_ihl & 0x0F) * 4  # Header length in bytes
    if ihl < IP_HEADER_MIN_SIZE:
        return None
    proto = ip_data[9]
    src_ip = '.'.join(str(b) for b in ip_data[12:16])
    dst_ip = '.'.join(str(b) for b in ip_data[16:20])
    return {
        'src': src_ip,
        'dst': dst_ip,
        'proto': proto,
        'data': ip_data[ihl:]  # Payload
    }

def parse_tcp(transport_data):
    """Parse TCP header: src/dst port."""
    if len(transport_data) < TCP_HEADER_MIN_SIZE:
        return None
    src_port, dst_port = struct.unpack('!HH', transport_data[:4])
    return src_port, dst_port

def parse_udp(transport_data):
    """Parse UDP header: src/dst port."""
    if len(transport_data) < UDP_HEADER_SIZE:
        return None
    src_port, dst_port = struct.unpack('!HHHH', transport_data[:8])[:2]
    return src_port, dst_port

def extract_metrics(packets):
    """Extract metrics using manual parsing."""
    talkers = Counter()
    ports = Counter()
    high_volume = []
    timestamps = []

    for pkt in packets:
        timestamps.append(pkt['ts'])
        ip_info = None
        dport = None

        # Parse layers
        eth_data = parse_ethernet(pkt['data'])
        if eth_data:
            ip_info = parse_ip(eth_data)
            if ip_info:
                src_ip, dst_ip = ip_info['src'], ip_info['dst']
                talkers[(src_ip, dst_ip)] += 1

                # Ports
                transport = ip_info['data']
                if ip_info['proto'] == 6:  # TCP
                    ports_info = parse_tcp(transport)
                    if ports_info:
                        dport = ports_info[1]  # Dst port
                elif ip_info['proto'] == 17:  # UDP
                    ports_info = parse_udp(transport)
                    if ports_info:
                        dport = ports_info[1]
                
                if dport:
                    ports[dport] += 1

    # High-volume (post-loop for simplicity)
    for conn, count in talkers.items():
        if count > 100:  # Adjust threshold for dummy (unlikely to hit)
            high_volume.append({'src': conn[0], 'dst': conn[1], 'packets': count})

    duration_min = (max(timestamps) - min(timestamps)) / 60 if timestamps else 0
    avg_rate = len(packets) / duration_min if duration_min > 0 else 0

    return {
        'total_packets': len(packets),
        'top_talkers': talkers.most_common(10),
        'top_ports': ports.most_common(10),
        'high_volume_connections': sorted(high_volume, key=lambda x: x['packets'], reverse=True),
        'avg_packets_per_min': round(avg_rate, 2)
    }

def detect_anomalies(packets):
    """Apply rules using manual parsing."""
    alerts = []
    src_rates = defaultdict(list)

    for pkt in packets:
        eth_data = parse_ethernet(pkt['data'])
        if not eth_data:
            continue
        ip_info = parse_ip(eth_data)
        if not ip_info:
            continue
        src = ip_info['src']
        src_rates[src].append(pkt['ts'])

        # Rule 1: DoS - High rate (>500 pkt/min; dummy won't trigger unless many packets)
        src_times = src_rates[src]
        if len(src_times) > 0:
            src_duration_min = (max(src_times) - min(src_times)) / 60
            src_rate = len(src_times) / src_duration_min if src_duration_min > 0 else 0
            if src_rate > 500:
                alerts.append({
                    'type': 'DoS_Suspicion',
                    'src_ip': src,
                    'rate_pkts_min': round(src_rate, 2),
                    'description': f'High packet rate from {src}: {src_rate:.0f} pkt/min'
                })

        # Rule 2: Unencrypted creds (scan raw payload for Basic Auth)
        transport = ip_info['data']
        if ip_info['proto'] == 6 and len(transport) > 50:  # TCP, assume payload after header
            try:
                payload = transport[TCP_HEADER_MIN_SIZE:].decode('utf-8', errors='ignore')  # Skip TCP header
                if 'Authorization: Basic' in payload:
                    auth_part = payload.split('Authorization: Basic ')[1].split('\n')[0].strip()
                    decoded = base64.b64decode(auth_part).decode('utf-8')
                    if ':' in decoded:
                        user, _ = decoded.split(':', 1)
                        alerts.append({
                            'type': 'Unencrypted_Creds',
                            'src_ip': src,
                            'details': f'Basic Auth detected: username "{user}" in HTTP payload',
                            'description': 'Potential credential leak over unencrypted HTTP'
                        })
            except:
                pass

    return alerts

def generate_report(metrics, alerts, output_file, csv=False, html=False):
    """Generate reports (CSV needs pandas; skip if not installed)."""
    report = {
        'analysis_date': datetime.now().isoformat(),
        'metrics': metrics,
        'alerts': alerts,
        'summary': f"{len(alerts)} anomalies detected in {metrics['total_packets']} packets"
    }

    # JSON output
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Report saved to {output_file}")

    # CSV (try import pandas)
    if csv:
        try:
            import pandas as pd
            df_talkers = pd.DataFrame([list(conn) + [count] for conn, count in metrics['top_talkers']], 
                                      columns=['Src_IP', 'Dst_IP', 'Packets'])
            df_ports = pd.DataFrame(metrics['top_ports'], columns=['Port', 'Packets'])
            df_talkers.to_csv('talkers.csv', index=False)
            df_ports.to_csv('ports.csv', index=False)
            print("CSV files saved: talkers.csv, ports.csv")
        except ImportError:
            print("Pandas not installed; skipping CSV output. Run 'pip install pandas' for CSV.")

    # HTML
    if html:
        html_content = f"""
        <html><body>
        <h1>Network Analysis Report</h1>
        <p>Summary: {report['summary']}</p>
        <h2>Alerts ({len(alerts)})</h2>
        <table border="1">
        <tr><th>Type</th><th>Description</th><th>Details</th></tr>
        """
        for alert in alerts:
            html_content += f"<tr><td>{alert['type']}</td><td>{alert['description']}</td><td>{alert.get('details', 'N/A')}</td></tr>"
        html_content += "</table><h2>Top Talkers</h2><ul>"
        for conn, count in metrics['top_talkers'][:5]:
            html_content += f"<li>{conn[0]} -> {conn[1]}: {count} packets</li>"
        html_content += "</ul></body></html>"
        with open('report.html', 'w') as f:
            f.write(html_content)
        print("HTML report saved: report.html")

def main():
    args = parse_arguments()
    
    # Handle file
    if not args.file:
        if args.no_dummy:
            print("No file provided and --no-dummy specified. Exiting.", file=sys.stderr)
            sys.exit(1)
        args.file = generate_dummy_pcap()
    elif not os.path.exists(args.file):
        print(f"File '{args.file}' not found. Use --no-dummy to skip dummy gen.", file=sys.stderr)
        sys.exit(1)
    
    print(f"Analyzing file: {args.file}")
    reader = PurePcapReader(args.file)
    packets = reader.load()
    metrics = extract_metrics(packets)
    alerts = detect_anomalies(packets)
    generate_report(metrics, alerts, args.output, args.csv, args.html)
    
    # Print summary
    print(f"\nQuick Summary:")
    print(f"- Total packets: {metrics['total_packets']}")
    print(f"- Avg rate: {metrics['avg_packets_per_min']:.1f} pkt/min")
    print(f"- Alerts: {len(alerts)} ({[a['type'] for a in alerts]})")
    if metrics['top_ports']:
        print(f"- Top port: {metrics['top_ports'][0][0]} ({metrics['top_ports'][0][1]} packets)")

if __name__ == "__main__":
    main()