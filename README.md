# NetTrace - Forensic Metadata Analysis Tool

NetTrace is a lawful, non-intrusive forensic tool that analyzes network metadata from encrypted communications to assist investigators in identifying remote communicating parties. It processes PCAP files, extracts flow statistics, profiles remote hosts behaviorally, and highlights suspicious patterns—all without decrypting any content.

## Features
- **PCAP Parsing**: Reads packet captures using Scapy.
- **Flow Reconstruction**: Groups packets into bidirectional flows.
- **Behavioral Profiling**: Computes per-remote IP statistics (session count, timing regularity, night activity, etc.) and a suspiciousness score.
- **Traffic Classification** (optional): Heuristic or ML-based identification of messaging, VoIP, or file transfer.
- **Geolocation & IP Reputation**: Maps IPs to countries/cities and detects VPN/Tor/proxy usage.
- **Interactive Dashboard**: Built with Dash, offering multiple views (flow table, timeline, network graph, suspicious hosts).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourname/NetTrace.git
   cd NetTrace
