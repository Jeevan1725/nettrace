"""
live_capture.py - FIXED VERSION
- Proper stop with AsyncSniffer
- PCAP written only on stop (no race condition)
- Basic app detection in live mode
"""

from scapy.all import AsyncSniffer, wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

import pandas as pd
import threading
import time
from ipaddress import ip_address, ip_network
from collections import Counter


class LiveCapture:
    def __init__(self, interface=None, packet_limit=10000):
        self.interface = interface
        self.packet_limit = packet_limit

        self.running = False
        self.sniffer = None

        self.packet_counter = 0
        self.metadata = []
        self.raw_packets = []          # ← now collected here, written only on stop

        self.lock = threading.Lock()

        # PCAP storage
        self.pcap_file = "live_capture.pcap"

        # App detection (copied from capture_parser for live use)
        self.app_ip_ranges = {
            'whatsapp': ['31.13.0.0/16', '157.240.0.0/16', '179.60.192.0/22', '185.60.216.0/22', '57.128.0.0/10'],
            'telegram': ['149.154.160.0/20', '91.108.0.0/16', '185.76.0.0/16'],
            'signal': ['3.208.0.0/12', '34.192.0.0/12'],
            'messenger': ['31.13.0.0/16', '157.240.0.0/16'],
            'discord': ['162.159.128.0/17', '162.159.192.0/17']
        }

    def _process_packet(self, packet):
        if not self.running:
            return

        try:
            pkt_info = None

            if IP in packet:
                ip_layer = packet[IP]
                pkt_info = {
                    "packet_num": self.packet_counter,
                    "timestamp": float(time.time()),
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "protocol": ip_layer.proto,
                    "length": len(packet),
                    "src_port": None,
                    "dst_port": None,
                    "tcp_flags": None,
                    "app_identified": "unknown",
                    "packet_type": "IPv4",
                    "is_local": ip_address(ip_layer.src).is_private or ip_address(ip_layer.dst).is_private
                }
                if TCP in packet:
                    tcp = packet[TCP]
                    pkt_info["src_port"] = tcp.sport
                    pkt_info["dst_port"] = tcp.dport
                    pkt_info["tcp_flags"] = str(tcp.flags)
                elif UDP in packet:
                    udp = packet[UDP]
                    pkt_info["src_port"] = udp.sport
                    pkt_info["dst_port"] = udp.dport

            elif IPv6 in packet:
                ipv6 = packet[IPv6]
                pkt_info = {
                    "packet_num": self.packet_counter,
                    "timestamp": float(time.time()),
                    "src_ip": ipv6.src,
                    "dst_ip": ipv6.dst,
                    "protocol": ipv6.nh,
                    "length": len(packet),
                    "src_port": None,
                    "dst_port": None,
                    "tcp_flags": None,
                    "app_identified": "unknown",
                    "packet_type": "IPv6",
                    "is_local": False
                }
                if TCP in packet:
                    tcp = packet[TCP]
                    pkt_info["src_port"] = tcp.sport
                    pkt_info["dst_port"] = tcp.dport
                    pkt_info["tcp_flags"] = str(tcp.flags)
                elif UDP in packet:
                    udp = packet[UDP]
                    pkt_info["src_port"] = udp.sport
                    pkt_info["dst_port"] = udp.dport

            if pkt_info:
                # === App detection in live ===
                dst = pkt_info.get("dst_ip", "")
                if dst and ":" not in dst:
                    for app, ranges in self.app_ip_ranges.items():
                        for r in ranges:
                            try:
                                if ip_address(dst) in ip_network(r):
                                    pkt_info["app_identified"] = app
                                    break
                            except:
                                pass
                        if pkt_info["app_identified"] != "unknown":
                            break

                with self.lock:
                    self.packet_counter += 1
                    self.metadata.append(pkt_info)
                    if len(self.metadata) > self.packet_limit:
                        self.metadata.pop(0)

                    self.raw_packets.append(packet)   # collect for later save

        except Exception as e:
            pass  # silent in live

    def start(self, interface=None):
        if self.running:
            return
        if interface:
            self.interface = interface

        print("🚀 Starting live capture with AsyncSniffer...")
        self.running = True
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
            filter="tcp or udp"
        )
        self.sniffer.start()

    def stop(self):
        if not self.running:
            return

        print("⏹ Stopping capture...")
        self.running = False
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None

        # === Write PCAP only once on stop ===
        with self.lock:
            if self.raw_packets:
                try:
                    wrpcap(self.pcap_file, self.raw_packets)
                    print(f"✅ PCAP saved: {self.pcap_file} ({len(self.raw_packets)} packets)")
                except Exception as e:
                    print(f"PCAP save error: {e}")
                self.raw_packets = []

    def get_dataframe(self):
        with self.lock:
            return pd.DataFrame(list(self.metadata)) if self.metadata else pd.DataFrame()

    def reset(self):
        with self.lock:
            self.metadata.clear()
            self.raw_packets.clear()
            self.packet_counter = 0

    def get_new_packets(self, last_index):
        with self.lock:
            if last_index >= len(self.metadata):
                return [], last_index

            new_packets = self.metadata[last_index:]
            return new_packets, len(self.metadata)