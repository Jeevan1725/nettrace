#!/usr/bin/env python3
# find_friend.py - Automatically find your friend's IP from WhatsApp capture

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
import sys
from collections import Counter

def find_friend(pcap_file, my_ip="192.168.21.243"):
    print(f"🔍 Analyzing {pcap_file}...")
    print(f"📱 Your IP: {my_ip}")
    
    # Read packets
    packets = rdpcap(pcap_file)
    
    # Track all IPs and timestamps
    local_ips = Counter()
    timestamps = []
    
    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            # Check for local IPs (192.168.21.x)
            if src.startswith('192.168.21.') and src != my_ip:
                local_ips[src] += 1
                timestamps.append((pkt.time, src, "src"))
            
            if dst.startswith('192.168.21.') and dst != my_ip:
                local_ips[dst] += 1
                timestamps.append((pkt.time, dst, "dst"))
    
    print(f"\n📊 Found {len(local_ips)} potential local devices:")
    for ip, count in local_ips.most_common():
        print(f"   • {ip}: appeared in {count} packets")
        
        # Show when this IP was active
        ip_times = [t for t in timestamps if t[1] == ip]
        if ip_times:
            first = min(ip_times)[0]
            last = max(ip_times)[0]
            from datetime import datetime
            print(f"     Active: {datetime.fromtimestamp(first).strftime('%H:%M:%S')} - "
                  f"{datetime.fromtimestamp(last).strftime('%H:%M:%S')}")
    
    if local_ips:
        most_likely = local_ips.most_common(1)[0][0]
        print(f"\n🎯 MOST LIKELY YOUR FRIEND: {most_likely}")
        print(f"   (appeared in {local_ips[most_likely]} packets)")
    else:
        print("\n❌ No local devices found in capture")
        print("   Make sure your friend is on the same WiFi and you captured during messaging")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python find_friend.py <pcap_file>")
        sys.exit(1)
    
    find_friend(sys.argv[1])
