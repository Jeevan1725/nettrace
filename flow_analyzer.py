"""
flow_analyzer.py
Reconstructs bidirectional flows from packet metadata and performs behavioral profiling.
Compatible with both offline PCAP analysis and live capture updates.
"""

import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime


class FlowAnalyzer:
    """
    Reconstructs network flows (5-tuple bidirectional) from packet DataFrame.
    """

    def __init__(self, packet_df: pd.DataFrame):
        self.packet_df = packet_df
        self.flows = None

    def reconstruct_flows(self, idle_timeout: int = 300) -> pd.DataFrame:
        """
        Group packets into bidirectional flows based on 5-tuple.
        Returns DataFrame with flow statistics.
        """
        if self.packet_df.empty:
            return pd.DataFrame()

        flow_dict = defaultdict(lambda: {
            'packets': [],
            'bytes_sent': 0,
            'bytes_received': 0,
            'start_time': float('inf'),
            'end_time': 0,
            'packet_sizes': [],
            'app': 'unknown'
        })

        required_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'timestamp', 'length']
        missing = [col for col in required_cols if col not in self.packet_df.columns]
        if missing:
            print(f"Warning: Missing columns for flow reconstruction: {missing}")
            return pd.DataFrame()

        for _, pkt in self.packet_df.iterrows():
            src_ip = pkt.get('src_ip', '')
            dst_ip = pkt.get('dst_ip', '')
            src_port = int(pkt['src_port']) if pd.notna(pkt.get('src_port')) else 0
            dst_port = int(pkt['dst_port']) if pd.notna(pkt.get('dst_port')) else 0
            proto    = int(pkt['protocol']) if pd.notna(pkt.get('protocol')) else 0
            app = pkt.get('app_identified', 'unknown')
            ts = pkt.get('timestamp', 0)
            length = int(pkt.get('length', 0))

            if not src_ip or not dst_ip or ts <= 0:
                continue

            # Create canonical (ordered) flow key
            if src_ip < dst_ip:
                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                direction = 'outgoing'
            else:
                flow_key = (dst_ip, src_ip, dst_port, src_port, proto)
                direction = 'incoming'

            f = flow_dict[flow_key]
            f['packets'].append(pkt.get('packet_num', -1))
            f['start_time'] = min(f['start_time'], ts)
            f['end_time'] = max(f['end_time'], ts)
            f['packet_sizes'].append(length)

            if f['app'] == 'unknown' and app != 'unknown':
                f['app'] = app

            if direction == 'outgoing':
                f['bytes_sent'] += length
            else:
                f['bytes_received'] += length

        records = []
        for key, val in flow_dict.items():
            if not val['packets']:
                continue

            duration = val['end_time'] - val['start_time']
            if duration <= 0:
                duration = 0.1  # avoid division by zero later

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
        if not self.flows.empty:
            self.flows = self.flows.sort_values('start_time')
        print(f"Reconstructed {len(self.flows)} flows")
        return self.flows

    def find_conversations(self) -> pd.DataFrame:
        """
        Aggregate flows into logical conversations (IP ↔ IP pairs).
        """
        if self.flows is None or self.flows.empty:
            return pd.DataFrame()

        conv_dict = defaultdict(lambda: {
            'flows': [],
            'total_packets': 0,
            'total_bytes': 0,
            'start_time': float('inf'),
            'end_time': 0,
            'apps': set()
        })

        for _, flow in self.flows.iterrows():
            ip_a, ip_b = sorted([flow['src_ip'], flow['dst_ip']])
            key = f"{ip_a}↔{ip_b}"

            conv = conv_dict[key]
            conv['flows'].append(flow.to_dict())
            conv['total_packets'] += flow['packet_count']
            conv['total_bytes'] += flow['total_bytes']
            conv['start_time'] = min(conv['start_time'], flow['start_time'])
            conv['end_time'] = max(conv['end_time'], flow['end_time'])
            conv['apps'].add(flow['app'])

        records = []
        for key, val in conv_dict.items():
            ip_a, ip_b = key.split("↔")
            records.append({
                'ip_a': ip_a,
                'ip_b': ip_b,
                'packet_count': val['total_packets'],
                'bytes_transferred': val['total_bytes'],
                'first_seen': val['start_time'],
                'last_seen': val['end_time'],
                'duration': val['end_time'] - val['start_time'],
                'app_used': ', '.join(val['apps']) if val['apps'] else 'unknown',
                'flow_count': len(val['flows'])
            })

        df = pd.DataFrame(records)
        if not df.empty:
            df = df.sort_values('packet_count', ascending=False)
        return df


class BehaviorProfiler:
    """
    Creates behavioral profiles for remote hosts based on flow statistics.
    """

    def __init__(self, flow_df: pd.DataFrame):
        self.flow_df = flow_df

    def profile_remote_hosts(self) -> pd.DataFrame:
        if self.flow_df.empty:
            return pd.DataFrame()

        profiles = []

        for ip in self.flow_df['dst_ip'].unique():
            ip_flows = self.flow_df[self.flow_df['dst_ip'] == ip].copy()
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
                'apps_used': ', '.join(ip_flows['app'].unique()),
                'suspicious_score': self._suspicious_score(ip_flows, night_ratio, regularity)
            }
            profiles.append(profile)

        df = pd.DataFrame(profiles)
        if not df.empty:
            df = df.sort_values('suspicious_score', ascending=False)
        return df

    def _hour_distribution(self, flows: pd.DataFrame) -> pd.Series:
        hours = []
        for ts in flows['start_time']:
            try:
                dt = datetime.fromtimestamp(ts)
                hours.append(dt.hour)
            except:
                continue
        return pd.Series(hours).value_counts().sort_index()

    def _night_activity_ratio(self, flows: pd.DataFrame) -> float:
        night = total = 0
        for ts in flows['start_time']:
            try:
                hour = datetime.fromtimestamp(ts).hour
                total += 1
                if hour >= 22 or hour <= 5:
                    night += 1
            except:
                continue
        return night / total if total > 0 else 0.0

    def _communication_regularity(self, flows: pd.DataFrame) -> float:
        if len(flows) < 2:
            return 1.0
        try:
            intervals = flows['start_time'].diff().dropna()
            if intervals.mean() <= 0:
                return 1.0
            return intervals.std() / intervals.mean()
        except:
            return 1.0

    def _suspicious_score(self, flows: pd.DataFrame, night_ratio: float, regularity: float) -> int:
        score = 0
        if regularity < 0.35:           # quite regular communication
            score += 35
        if night_ratio > 0.65:          # mostly nighttime activity
            score += 35
        if flows['avg_packet_size'].mean() < 320:  # small packets → likely messaging
            score += 20
        if len(flows) > 12:             # many sessions
            score += 10
        return min(score, 100)


# ────────────────────────────────────────────────
# Quick test / standalone usage
# ────────────────────────────────────────────────

if __name__ == "__main__":
    # Example usage (for debugging)
    print("This module is meant to be imported.")
    print("Example:")
    print("  analyzer = FlowAnalyzer(packet_dataframe)")
    print("  flows = analyzer.reconstruct_flows()")
    print("  convs = analyzer.find_conversations()")
    print("  profiler = BehaviorProfiler(flows)")
    print("  profiles = profiler.profile_remote_hosts()")
