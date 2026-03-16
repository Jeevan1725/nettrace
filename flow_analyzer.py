"""
flow_analyzer.py
Reconstructs flows from packet metadata, performs behavioral profiling,
and identifies communication patterns.
"""

import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime

class FlowAnalyzer:
    def __init__(self, packet_df):
        self.packet_df = packet_df
        self.flows = None

    def reconstruct_flows(self, idle_timeout=300):
        """
        Group packets into bidirectional flows (5-tuple).
        Returns a DataFrame of flow statistics.
        """
        flow_dict = defaultdict(lambda: {
            'packets': [],
            'bytes_sent': 0,
            'bytes_received': 0,
            'start_time': float('inf'),
            'end_time': 0,
            'packet_sizes': [],
            'app': 'unknown'
        })

        for _, pkt in self.packet_df.iterrows():
            src_ip = pkt.get('src_ip', '')
            dst_ip = pkt.get('dst_ip', '')
            src_port = pkt.get('src_port', 0) if pkt.get('src_port') else 0
            dst_port = pkt.get('dst_port', 0) if pkt.get('dst_port') else 0
            proto = pkt.get('protocol', 0)
            app = pkt.get('app_identified', 'unknown')
            
            if not src_ip or not dst_ip:
                continue

            # Create ordered flow key
            if src_ip < dst_ip:
                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                direction = 'outgoing'
            else:
                flow_key = (dst_ip, src_ip, dst_port, src_port, proto)
                direction = 'incoming'

            f = flow_dict[flow_key]
            f['packets'].append(pkt.get('packet_num', 0))
            f['start_time'] = min(f['start_time'], pkt.get('timestamp', 0))
            f['end_time'] = max(f['end_time'], pkt.get('timestamp', 0))
            f['packet_sizes'].append(pkt.get('length', 0))
            
            # Update app if we found one
            if f['app'] == 'unknown' and app != 'unknown':
                f['app'] = app

            if direction == 'outgoing':
                f['bytes_sent'] += pkt.get('length', 0)
            else:
                f['bytes_received'] += pkt.get('length', 0)

        records = []
        for key, val in flow_dict.items():
            if len(val['packets']) == 0:
                continue
                
            duration = val['end_time'] - val['start_time']
            if duration <= 0:
                duration = 0.1
                
            records.append({
                'src_ip': key[0],
                'dst_ip': key[1],
                'src_port': key[2],
                'dst_port': key[3],
                'protocol': key[4],
                'app': val['app'],
                'start_time': val['start_time'],
                'end_time': val['end_time'],
                'duration': duration,
                'packet_count': len(val['packets']),
                'bytes_sent': val['bytes_sent'],
                'bytes_received': val['bytes_received'],
                'total_bytes': val['bytes_sent'] + val['bytes_received'],
                'avg_packet_size': np.mean(val['packet_sizes']) if val['packet_sizes'] else 0,
                'packet_size_std': np.std(val['packet_sizes']) if len(val['packet_sizes']) > 1 else 0
            })

        self.flows = pd.DataFrame(records)
        print(f"Reconstructed {len(self.flows)} flows")
        return self.flows

    def find_conversations(self):
        """
        Identify bidirectional conversations between two IPs
        """
        if self.flows is None or self.flows.empty:
            return pd.DataFrame()
        
        conversations = {}
        
        for _, flow in self.flows.iterrows():
            ip_a = flow.get('src_ip', '')
            ip_b = flow.get('dst_ip', '')
            
            if not ip_a or not ip_b:
                continue
                
            # Create ordered pair
            try:
                ip1, ip2 = sorted([ip_a, ip_b])
            except:
                continue
                
            key = f"{ip1}↔{ip2}"
            
            if key not in conversations:
                conversations[key] = {
                    'participant_a': ip1,
                    'participant_b': ip2,
                    'flows': [],
                    'total_packets': 0,
                    'total_bytes': 0,
                    'start_time': flow.get('start_time', 0),
                    'end_time': flow.get('end_time', 0),
                    'apps': set()
                }
            
            conv = conversations[key]
            conv['flows'].append(flow.to_dict())
            conv['total_packets'] += flow.get('packet_count', 0)
            conv['total_bytes'] += flow.get('total_bytes', 0)
            conv['start_time'] = min(conv['start_time'], flow.get('start_time', 0))
            conv['end_time'] = max(conv['end_time'], flow.get('end_time', 0))
            if flow.get('app', 'unknown') != 'unknown':
                conv['apps'].add(flow.get('app', 'unknown'))
        
        # Convert to list of dicts for DataFrame
        result = []
        for key, val in conversations.items():
            # Only include if it has meaningful traffic
            if val['total_packets'] >= 4:
                result.append({
                    'participant_a': val['participant_a'],
                    'participant_b': val['participant_b'],
                    'conversation_id': key,
                    'flow_count': len(val['flows']),
                    'total_packets': val['total_packets'],
                    'total_bytes': val['total_bytes'],
                    'duration': val['end_time'] - val['start_time'],
                    'start_time': val['start_time'],
                    'end_time': val['end_time'],
                    'apps_used': ', '.join(val['apps']) if val['apps'] else 'unknown',
                    'message_count': self._estimate_message_count(val['total_packets'])
                })
        
        return pd.DataFrame(result)
    
    def _estimate_message_count(self, total_packets):
        """Estimate number of messages based on packet patterns"""
        # For encrypted messaging, each message is typically 1-3 packets
        return max(1, total_packets // 2)

    def get_communication_timeline(self, conversation_key):
        """Get detailed timeline for a specific conversation"""
        if self.flows is None or self.flows.empty:
            return pd.DataFrame()
        
        # Parse conversation key
        try:
            ip_a, ip_b = conversation_key.split('↔')
        except:
            return pd.DataFrame()
        
        # Get all flows between these IPs
        mask = ((self.flows['src_ip'] == ip_a) & (self.flows['dst_ip'] == ip_b)) | \
               ((self.flows['src_ip'] == ip_b) & (self.flows['dst_ip'] == ip_a))
        
        conversation_flows = self.flows[mask].copy()
        
        if conversation_flows.empty:
            return conversation_flows
        
        # Sort by time
        conversation_flows = conversation_flows.sort_values('start_time')
        
        # Add direction indicator
        conversation_flows['direction'] = conversation_flows.apply(
            lambda x: f"{x['src_ip']}→{x['dst_ip']}", axis=1)
        
        return conversation_flows


class BehaviorProfiler:
    def __init__(self, flow_df):
        self.flow_df = flow_df

    def profile_remote_hosts(self):
        """
        Generate behavioral profiles for each unique remote IP.
        Returns a DataFrame with one row per IP.
        """
        if self.flow_df.empty:
            return pd.DataFrame()
            
        profiles = []
        for ip in self.flow_df['dst_ip'].unique():
            ip_flows = self.flow_df[self.flow_df['dst_ip'] == ip]
            if ip_flows.empty:
                continue

            hour_dist = self._hour_distribution(ip_flows)
            night_ratio = self._night_activity_ratio(ip_flows)
            regularity = self._communication_regularity(ip_flows)

            profile = {
                'remote_ip': ip,
                'total_sessions': len(ip_flows),
                'total_bytes': ip_flows['total_bytes'].sum(),
                'avg_session_duration': ip_flows['duration'].mean(),
                'avg_packet_size': ip_flows['avg_packet_size'].mean(),
                'communication_regularity': regularity,
                'peak_activity_hour': hour_dist.idxmax() if not hour_dist.empty else -1,
                'night_activity_ratio': night_ratio,
                'apps_used': ', '.join(ip_flows['app'].unique()) if 'app' in ip_flows.columns else 'unknown',
                'suspicious_score': self._suspicious_score(ip_flows, night_ratio, regularity)
            }
            profiles.append(profile)

        return pd.DataFrame(profiles)

    def _hour_distribution(self, flows):
        hours = []
        for _, flow in flows.iterrows():
            try:
                dt = datetime.fromtimestamp(flow['start_time'])
                hours.append(dt.hour)
            except:
                continue
        return pd.Series(hours).value_counts().sort_index()

    def _night_activity_ratio(self, flows):
        night = 0
        total = 0
        for _, flow in flows.iterrows():
            try:
                hour = datetime.fromtimestamp(flow['start_time']).hour
                total += 1
                if hour >= 22 or hour <= 5:
                    night += 1
            except:
                continue
        return night / total if total > 0 else 0

    def _communication_regularity(self, flows):
        if len(flows) < 2:
            return 1.0
        try:
            intervals = flows['start_time'].diff().dropna()
            if intervals.mean() == 0:
                return 1.0
            return intervals.std() / intervals.mean()
        except:
            return 1.0

    def _suspicious_score(self, flows, night_ratio, regularity):
        score = 0
        if regularity < 0.3:  # Very regular
            score += 40
        if night_ratio > 0.7:  # Mostly at night
            score += 40
        if flows['avg_packet_size'].mean() < 300:  # Small packets (messaging)
            score += 20
        if len(flows) > 10:  # Many sessions
            score += 10
        return min(score, 100)


class TrafficClassifier:
    def __init__(self, model_path=None):
        self.model = None

    def extract_features(self, flow_df):
        """Extract features for classification"""
        X = []
        for _, flow in flow_df.iterrows():
            features = [
                flow.get('duration', 0),
                flow.get('packet_count', 0),
                flow.get('avg_packet_size', 0),
                flow.get('packet_size_std', 0),
                flow.get('bytes_sent', 0) / (flow.get('bytes_received', 0) + 1),
                len(flow_df[flow_df['dst_ip'] == flow.get('dst_ip', '')]) if 'dst_ip' in flow_df.columns else 0
            ]
            X.append(features)
        return np.array(X) if X else np.array([])

    def predict(self, flow_df):
        """Heuristic-based traffic type classification"""
        results = []
        for _, flow in flow_df.iterrows():
            avg_size = flow.get('avg_packet_size', 0)
            duration = flow.get('duration', 0)
            packet_count = flow.get('packet_count', 0)
            app = flow.get('app', 'unknown')
            
            # If app is already identified, use that
            if app in ['whatsapp', 'telegram', 'signal', 'messenger']:
                results.append('messaging')
            elif avg_size < 300 and duration < 60 and packet_count > 5:
                results.append('messaging')
            elif avg_size > 1000 and duration > 120:
                results.append('file_transfer')
            elif packet_count > 100 and duration < 300 and avg_size > 500:
                results.append('voip')
            else:
                results.append('unknown')
        return results
