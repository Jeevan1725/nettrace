"""
utils/reputation.py
Check IP against known VPN, Tor, proxy lists.
"""

import socket

class IPReputation:
    def __init__(self):
        # Sample Tor exit nodes (would be updated regularly in production)
        self.tor_exit_nodes = {
            '185.220.101.1', '185.220.101.2', '185.220.101.3',
            '171.25.193.20', '171.25.193.25', '171.25.193.78'
        }
        
        # Known VPN/proxy IP ranges (simplified)
        self.vpn_indicators = [
            'vpn', 'proxy', 'tor', 'exit', 'relay', 'secure', 'private'
        ]

    def check(self, ip):
        """
        Returns a dict with reputation info.
        """
        result = {
            'ip': ip,
            'is_vpn': False,
            'is_tor': False,
            'is_proxy': False,
            'hostname': None,
            'anonymizer': None
        }
        
        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result['hostname'] = hostname
            # Check for anonymizer indicators in hostname
            hostname_lower = hostname.lower()
            for indicator in self.vpn_indicators:
                if indicator in hostname_lower:
                    result['anonymizer'] = indicator
                    result['is_vpn'] = True
                    break
        except:
            pass

        # Check against Tor exit node list
        if ip in self.tor_exit_nodes:
            result['is_tor'] = True
            result['anonymizer'] = 'tor'
            result['is_vpn'] = True

        # Check for private/rfc1918 addresses
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                         '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                         '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                         '172.30.', '172.31.', '192.168.')):
            result['is_vpn'] = False  # These are local networks, not VPNs

        return result
