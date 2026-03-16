"""
utils/geoip.py
IP geolocation using MaxMind GeoLite2 database.
"""

import os

class GeoIP:
    def __init__(self, db_path='data/GeoLite2-City.mmdb'):
        self.db_path = db_path
        self.reader = None
        # Try to import geoip2 only if available
        try:
            import geoip2.database
            if os.path.exists(db_path):
                self.reader = geoip2.database.Reader(db_path)
        except ImportError:
            print("geoip2 not installed. Install with: pip install geoip2")
        except Exception as e:
            print(f"Failed to load GeoIP database: {e}")

    def lookup(self, ip):
        """Return (country, city) tuple or (None, None) if not found."""
        if not self.reader:
            return None, None
        try:
            response = self.reader.city(ip)
            country = response.country.name
            city = response.city.name
            return country, city
        except:
            return None, None
