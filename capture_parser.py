"""
capture_parser.py
Extracts metadata from PCAP files using Scapy.
With enhanced app detection and local peer discovery.
"""

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNSQR
import pandas as pd
import os
from ipaddress import ip_address, ip_network
import socket
from collections import Counter

class PCAPParser:
    def __init__(self, pcap_path):
        """
        Initialize with path to PCAP file.
        """
        self.pcap_path = pcap_path
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        self.packets = rdpcap(pcap_path)
        self.metadata = []
        self.dns_cache = {}
        self.suspect_ip = None
        self.local_network = '192.168.21.'  # Your local network
        
        # Known messaging app domains
        self.app_domains = {
            'whatsapp': [
                'whatsapp.net', 'whatsapp.com', 'wa.me', 
                'web.whatsapp.com', 'cdn.whatsapp.net',
                'static.whatsapp.net', 'mmg.whatsapp.net',
                'media.wa.me', 'pps.whatsapp.net',
                'mmx-ds.cdn.whatsapp.net', 'mmx-ds.whatsapp.net'
            ],
            'telegram': [
                'telegram.org', 't.me', 'telegram.me',
                'web.telegram.org', 'venus.web.telegram.org',
                'pluto.web.telegram.org', 'mars.web.telegram.org'
            ],
            'signal': [
                'signal.org', 'whispersystems.org',
                'chat.signal.org', 'storage.signal.org'
            ],
            'messenger': [
                'messenger.com', 'facebook.com', 'fb.com',
                'fbsbx.com', 'fbcdn.net'
            ],
            'discord': [
                'discord.com', 'discord.gg', 'discordapp.com',
                'discord.media'
            ]
        }
        
        # Known messaging app IP ranges (EXPANDED)
        self.app_ip_ranges = {
            'whatsapp': [
                '31.13.0.0/16', '157.240.0.0/16', '179.60.192.0/22',
                '185.60.216.0/22', '5.157.0.0/16', '57.128.0.0/10',
                '57.144.0.0/12', '57.144.0.0/16', '57.144.211.0/24',
                '50.22.0.0/15', '169.44.0.0/16', '169.45.0.0/16',
                '169.46.0.0/16', '169.47.0.0/16', '169.48.0.0/16',
                '169.49.0.0/16', '169.50.0.0/16', '169.51.0.0/16',
                '169.52.0.0/16', '169.53.0.0/16', '169.54.0.0/16',
                '169.55.0.0/16', '23.0.0.0/12', '23.32.0.0/11',
                '151.101.0.0/16'
            ],
            'telegram': [
                '149.154.160.0/20', '91.108.0.0/16', '109.239.140.0/24',
                '185.76.0.0/16', '95.161.0.0/16', '91.105.0.0/16',
                '91.108.12.0/22', '91.108.16.0/21'
            ],
            'signal': [
                '3.208.0.0/12', '34.192.0.0/12', '35.168.0.0/13',
                '18.208.0.0/13', '52.200.0.0/13', '34.224.0.0/12',
                '52.0.0.0/15', '54.80.0.0/13', '54.160.0.0/13'
            ],
            'facebook': [
                '31.13.0.0/16', '157.240.0.0/16', '69.171.224.0/20',
                '185.60.216.0/22', '179.60.192.0/22'
            ],
            'discord': [
                '162.159.128.0/17', '162.159.192.0/17', '132.254.0.0/16'
            ]
        }
        
    def extract_metadata(self):
        """
        Extract basic packet information with local peer detection
        """
        print(f"Processing {len(self.packets)} packets...")
        ip_count = 0
        all_src_ips = []
        
        for i, packet in enumerate(self.packets):
            if IP in packet:
                ip_layer = packet[IP]
                ip_count += 1
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                all_src_ips.append(src_ip)
                
                pkt_info = {
                    'packet_num': i,
                    'timestamp': float(packet.time),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': ip_layer.proto,
                    'length': len(packet),
                    'src_port': None,
                    'dst_port': None,
                    'tcp_flags': None,
                    'app_identified': 'unknown',
                    'packet_type': 'IPv4',
                    'is_local': self._is_local_ip(src_ip) or self._is_local_ip(dst_ip)
                }
                
                if TCP in packet:
                    tcp = packet[TCP]
                    pkt_info['src_port'] = tcp.sport
                    pkt_info['dst_port'] = tcp.dport
                    pkt_info['tcp_flags'] = str(tcp.flags)
                elif UDP in packet:
                    udp = packet[UDP]
                    pkt_info['src_port'] = udp.sport
                    pkt_info['dst_port'] = udp.dport
                
                self.metadata.append(pkt_info)
            
            elif IPv6 in packet:
                ipv6_layer = packet[IPv6]
                ip_count += 1
                src_ip = ipv6_layer.src
                dst_ip = ipv6_layer.dst
                all_src_ips.append(src_ip)
                
                pkt_info = {
                    'packet_num': i,
                    'timestamp': float(packet.time),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': ipv6_layer.nh,
                    'length': len(packet),
                    'src_port': None,
                    'dst_port': None,
                    'tcp_flags': None,
                    'app_identified': 'unknown',
                    'packet_type': 'IPv6',
                    'is_local': False
                }
                
                if TCP in packet:
                    tcp = packet[TCP]
                    pkt_info['src_port'] = tcp.sport
                    pkt_info['dst_port'] = tcp.dport
                    pkt_info['tcp_flags'] = str(tcp.flags)
                elif UDP in packet:
                    udp = packet[UDP]
                    pkt_info['src_port'] = udp.sport
                    pkt_info['dst_port'] = udp.dport
                
                self.metadata.append(pkt_info)

        # Identify suspect IP (most frequent source)
        if all_src_ips:
            self.suspect_ip = Counter(all_src_ips).most_common(1)[0][0]
            print(f"🔍 Suspect IP identified: {self.suspect_ip}")

        print(f"Found {ip_count} IP packets")
        
        if not self.metadata:
            return pd.DataFrame()
            
        df = pd.DataFrame(self.metadata)
        df = self._identify_apps_by_ip(df)
        
        # Find local peers
        local_peers = self._find_local_peers(df)
        if local_peers:
            print(f"👥 Local peers detected: {local_peers}")
        
        return df

    def _is_local_ip(self, ip):
        """Check if IP is in local network"""
        return ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                              '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                              '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                              '172.30.', '172.31.'))

    def _find_local_peers(self, df):
        """Find other devices in same local network"""
        local_ips = set()
        for ip in df['src_ip'].unique():
            if self._is_local_ip(ip) and ip != self.suspect_ip:
                local_ips.add(ip)
        for ip in df['dst_ip'].unique():
            if self._is_local_ip(ip) and ip != self.suspect_ip:
                local_ips.add(ip)
        return local_ips

    def _identify_apps_by_ip(self, df):
        """Identify apps based on destination IP ranges"""
        for idx, row in df.iterrows():
            dst_ip = row.get('dst_ip', '')
            if not dst_ip or ':' in dst_ip:
                continue
                
            for app, ip_ranges in self.app_ip_ranges.items():
                for ip_range in ip_ranges:
                    if self._ip_in_range(dst_ip, ip_range):
                        df.at[idx, 'app_identified'] = app
                        break
                if df.at[idx, 'app_identified'] != 'unknown':
                    break
        return df

    def get_dns_queries(self):
        """Extract DNS queries from the capture"""
        dns_records = []
        for packet in self.packets:
            if DNSQR in packet:
                ip_src = None
                ip_dst = None
                
                if IP in packet:
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                elif IPv6 in packet:
                    ip_src = packet[IPv6].src
                    ip_dst = packet[IPv6].dst
                else:
                    continue
                
                dns = packet[DNSQR]
                query_name = dns.qname.decode() if isinstance(dns.qname, bytes) else dns.qname
                if query_name.endswith('.'):
                    query_name = query_name[:-1]
                    
                dns_records.append({
                    'timestamp': packet.time,
                    'query': query_name.lower(),
                    'src_ip': ip_src,
                    'dst_ip': ip_dst
                })
                
                self.dns_cache[ip_dst] = query_name.lower()
                
        return pd.DataFrame(dns_records)

    def identify_apps(self):
        """Identify messaging apps used"""
        apps_detected = {}
        
        # Check DNS queries
        dns_df = self.get_dns_queries()
        if not dns_df.empty:
            for _, row in dns_df.iterrows():
                query = row['query'].lower()
                for app, domains in self.app_domains.items():
                    if any(domain in query for domain in domains):
                        apps_detected[app] = apps_detected.get(app, 0) + 1
                        self._tag_packets_by_dns(row['dst_ip'], app)
        
        # Check IP ranges
        if self.metadata:
            dst_ips = set(pkt.get('dst_ip') for pkt in self.metadata if pkt.get('dst_ip'))
            for ip in dst_ips:
                if ':' in ip:
                    continue
                for app, ip_ranges in self.app_ip_ranges.items():
                    for ip_range in ip_ranges:
                        if self._ip_in_range(ip, ip_range):
                            apps_detected[app] = apps_detected.get(app, 0) + 1
                            self._tag_packets_by_ip(ip, app)
        
        return apps_detected

    def _tag_packets_by_dns(self, ip, app):
        """Tag packets by DNS resolution"""
        for pkt in self.metadata:
            if pkt.get('dst_ip') == ip and pkt.get('app_identified') == 'unknown':
                pkt['app_identified'] = app

    def _tag_packets_by_ip(self, ip, app):
        """Tag packets by IP range"""
        for pkt in self.metadata:
            if pkt.get('dst_ip') == ip and pkt.get('app_identified') == 'unknown':
                pkt['app_identified'] = app

    def _ip_in_range(self, ip, ip_range):
        """Check if IP is in CIDR range"""
        try:
            return ip_address(ip) in ip_network(ip_range)
        except:
            try:
                ip_parts = ip.split('.')
                range_parts = ip_range.split('/')[0].split('.')
                return ip_parts[0] == range_parts[0] and ip_parts[1] == range_parts[1]
            except:
                return False

    def get_conversation_pairs(self):
        """
        Identify ALL conversation pairs including local peers
        """
        try:
            if not self.metadata or len(self.metadata) == 0:
                return pd.DataFrame()
            
            conversations = {}
            local_peers = set()
            
            # Identify suspect IP if not already set
            if not self.suspect_ip:
                src_ips = [pkt.get('src_ip') for pkt in self.metadata if pkt.get('src_ip')]
                if src_ips:
                    self.suspect_ip = Counter(src_ips).most_common(1)[0][0]
            
            for pkt in self.metadata:
                src_ip = pkt.get('src_ip', '')
                dst_ip = pkt.get('dst_ip', '')
                
                if not src_ip or not dst_ip:
                    continue
                
                # Track local peers
                if self._is_local_ip(dst_ip) and dst_ip != self.suspect_ip:
                    local_peers.add(dst_ip)
                if self._is_local_ip(src_ip) and src_ip != self.suspect_ip:
                    local_peers.add(src_ip)
                
                # Skip multicast/broadcast
                if dst_ip.startswith(('224.', '239.', '255.', 'ff02')):
                    continue
                
                # Create ordered pair
                try:
                    if ':' in src_ip or ':' in dst_ip:
                        ip1, ip2 = sorted([src_ip, dst_ip])
                    else:
                        ip1_num = int(ip_address(src_ip))
                        ip2_num = int(ip_address(dst_ip))
                        if ip1_num < ip2_num:
                            ip1, ip2 = src_ip, dst_ip
                        else:
                            ip1, ip2 = dst_ip, src_ip
                except:
                    ip1, ip2 = sorted([src_ip, dst_ip])
                
                key = f"{ip1}↔{ip2}"
                
                if key not in conversations:
                    conversations[key] = {
                        'ip_a': ip1,
                        'ip_b': ip2,
                        'packet_count': 0,
                        'bytes_transferred': 0,
                        'first_seen': pkt.get('timestamp', 0),
                        'last_seen': pkt.get('timestamp', 0),
                        'app_used': pkt.get('app_identified', 'unknown'),
                        'is_local_both': self._is_local_ip(ip1) and self._is_local_ip(ip2),
                        'involves_suspect': (ip1 == self.suspect_ip or ip2 == self.suspect_ip),
                        'involves_peer': False
                    }
                
                conv = conversations[key]
                conv['packet_count'] += 1
                conv['bytes_transferred'] += pkt.get('length', 0)
                conv['last_seen'] = max(conv['last_seen'], pkt.get('timestamp', 0))
                
                # Check if involves a local peer
                if (ip1 in local_peers or ip2 in local_peers) and conv['involves_suspect']:
                    conv['involves_peer'] = True
            
            # Print local peers found
            if local_peers:
                print(f"\n🎯 LOCAL PEERS DETECTED: {local_peers}")
                print("These could be your friend's devices!\n")
            
            # Format results
            result = []
            for conv in conversations.values():
                # Include if it's meaningful traffic
                if conv['packet_count'] >= 4:
                    # Calculate if this is a messaging conversation
                    is_messaging = (conv['app_used'] in ['whatsapp', 'telegram', 'signal'] or 
                                   conv['packet_count'] > 20)
                    
                    result.append({
                        'ip_a': conv['ip_a'],
                        'ip_b': conv['ip_b'],
                        'packet_count': conv['packet_count'],
                        'bytes_transferred': conv['bytes_transferred'],
                        'first_seen': conv['first_seen'],
                        'last_seen': conv['last_seen'],
                        'app_used': conv['app_used'],
                        'duration': conv['last_seen'] - conv['first_seen'],
                        'is_local_both': conv['is_local_both'],
                        'involves_suspect': conv['involves_suspect'],
                        'involves_peer': conv['involves_peer'],
                        'is_messaging': is_messaging
                    })
            
            # Sort by involvement with suspect
            result.sort(key=lambda x: (x['involves_suspect'], x['packet_count']), reverse=True)
            
            if local_peers:
                print(f"Found {len(result)} conversations, including potential peer-to-peer!")
            
            return pd.DataFrame(result)
            
        except Exception as e:
            print(f"Error in get_conversation_pairs: {e}")
            import traceback
            traceback.print_exc()
            return pd.DataFrame()
