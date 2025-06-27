import requests
import json
from typing import Dict, Optional, List
from datetime import datetime
import ipaddress
import sqlite3
from pathlib import Path

class ThreatIntelligence:
    """Advanced threat intelligence and IP analysis."""
    
    def __init__(self, db_path: str = "honeypot.db"):
        self.db_path = db_path
        self.threat_feeds = {
            "malicious_ips": self._load_threat_ips(),
            "tor_nodes": self._load_tor_nodes(),
            "known_botnets": self._load_botnet_ips()
        }
        self._init_threat_db()

    def _init_threat_db(self):
        """Initialize threat intelligence database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY,
                ip_address TEXT UNIQUE,
                threat_type TEXT,
                confidence_score REAL,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                source TEXT,
                additional_info TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_geolocation (
                id INTEGER PRIMARY KEY,
                ip_address TEXT UNIQUE,
                country TEXT,
                region TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                isp TEXT,
                organization TEXT,
                asn TEXT,
                timezone TEXT,
                last_updated TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def analyze_ip(self, ip_address: str) -> Dict:
        """Comprehensive IP analysis."""
        analysis = {
            "ip_address": ip_address,
            "timestamp": datetime.now().isoformat(),
            "threat_level": "unknown",
            "geolocation": {},
            "threat_indicators": [],
            "reputation_score": 0,
            "is_tor": False,
            "is_vpn": False,
            "is_datacenter": False
        }
        
        # Check if IP is in threat feeds
        analysis["threat_indicators"] = self._check_threat_feeds(ip_address)
        analysis["threat_level"] = self._calculate_threat_level(analysis["threat_indicators"])
        
        # Get geolocation data
        analysis["geolocation"] = self._get_geolocation(ip_address)
        
        # Check for special IP types
        analysis["is_tor"] = self._is_tor_node(ip_address)
        analysis["is_vpn"] = self._is_vpn(ip_address)
        analysis["is_datacenter"] = self._is_datacenter(ip_address)
        
        # Calculate reputation score
        analysis["reputation_score"] = self._calculate_reputation_score(analysis)
        
        # Store in database
        self._store_threat_intel(ip_address, analysis)
        
        return analysis

    def _check_threat_feeds(self, ip_address: str) -> List[Dict]:
        """Check IP against known threat feeds."""
        threats = []
        
        # Check malicious IPs
        if ip_address in self.threat_feeds["malicious_ips"]:
            threats.append({
                "type": "malicious_ip",
                "confidence": 0.9,
                "source": "threat_feed",
                "description": "IP found in known malicious IP list"
            })
        
        # Check Tor nodes
        if ip_address in self.threat_feeds["tor_nodes"]:
            threats.append({
                "type": "tor_node",
                "confidence": 1.0,
                "source": "tor_directory",
                "description": "Tor exit node"
            })
        
        # Check botnets
        if ip_address in self.threat_feeds["known_botnets"]:
            threats.append({
                "type": "botnet",
                "confidence": 0.8,
                "source": "botnet_tracker",
                "description": "Known botnet member"
            })
        
        return threats

    def _get_geolocation(self, ip_address: str) -> Dict:
        """Get geolocation data for IP address."""
        # First check database cache
        cached = self._get_cached_geolocation(ip_address)
        if cached:
            return cached
        
        # Mock geolocation service (in real implementation, use ipinfo.io, MaxMind, etc.)
        mock_geolocations = {
            "45.142.212.33": {
                "country": "Russia",
                "region": "Moscow",
                "city": "Moscow",
                "latitude": 55.7558,
                "longitude": 37.6176,
                "isp": "Unknown ISP",
                "organization": "Unknown",
                "asn": "AS12345",
                "timezone": "Europe/Moscow"
            },
            "198.51.100.42": {
                "country": "China",
                "region": "Beijing",
                "city": "Beijing",
                "latitude": 39.9042,
                "longitude": 116.4074,
                "isp": "Alibaba Cloud",
                "organization": "Alibaba",
                "asn": "AS37963",
                "timezone": "Asia/Shanghai"
            }
        }
        
        geo_data = mock_geolocations.get(ip_address, {
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "isp": "Unknown",
            "organization": "Unknown",
            "asn": "Unknown",
            "timezone": "Unknown"
        })
        
        # Cache the result
        self._cache_geolocation(ip_address, geo_data)
        
        return geo_data

    def _calculate_threat_level(self, threats: List[Dict]) -> str:
        """Calculate overall threat level."""
        if not threats:
            return "low"
        
        max_confidence = max(threat["confidence"] for threat in threats)
        threat_types = [threat["type"] for threat in threats]
        
        if "botnet" in threat_types or "malicious_ip" in threat_types:
            return "critical"
        elif "tor_node" in threat_types or max_confidence > 0.7:
            return "high"
        elif max_confidence > 0.5:
            return "medium"
        else:
            return "low"

    def _calculate_reputation_score(self, analysis: Dict) -> int:
        """Calculate IP reputation score (0-100, lower is worse)."""
        score = 100
        
        for threat in analysis["threat_indicators"]:
            if threat["type"] == "malicious_ip":
                score -= 80
            elif threat["type"] == "botnet":
                score -= 70
            elif threat["type"] == "tor_node":
                score -= 30
        
        if analysis["is_datacenter"]:
            score -= 20
        if analysis["is_vpn"]:
            score -= 15
        
        return max(0, score)

    def _load_threat_ips(self) -> set:
        """Load known malicious IPs."""
        return {
            "45.142.212.33", "103.224.182.245", "91.243.44.13",
            "185.220.101.42", "198.51.100.42", "203.0.113.195"
        }

    def _load_tor_nodes(self) -> set:
        """Load known Tor exit nodes."""
        return {
            "185.220.101.42", "199.87.154.255", "185.220.102.8"
        }

    def _load_botnet_ips(self) -> set:
        """Load known botnet IPs."""
        return {
            "103.224.182.245", "45.142.212.33"
        }

    def _is_tor_node(self, ip_address: str) -> bool:
        """Check if IP is a Tor node."""
        return ip_address in self.threat_feeds["tor_nodes"]

    def _is_vpn(self, ip_address: str) -> bool:
        """Check if IP is from a VPN service."""
        # Mock VPN detection logic
        vpn_asns = ["AS62240", "AS396356", "AS13335"]  # Example VPN ASNs
        return False  # Simplified for demo

    def _is_datacenter(self, ip_address: str) -> bool:
        """Check if IP is from a datacenter."""
        # Mock datacenter detection
        return "cloud" in self._get_geolocation(ip_address).get("organization", "").lower()

    def _store_threat_intel(self, ip_address: str, analysis: Dict):
        """Store threat intelligence in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO threat_intel 
            (ip_address, threat_type, confidence_score, first_seen, last_seen, source, additional_info)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            ip_address,
            analysis["threat_level"],
            analysis["reputation_score"] / 100,
            datetime.now(),
            datetime.now(),
            "internal_analysis",
            json.dumps(analysis["threat_indicators"])
        ))
        
        conn.commit()
        conn.close()

    def _get_cached_geolocation(self, ip_address: str) -> Optional[Dict]:
        """Get cached geolocation data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT country, region, city, latitude, longitude, isp, organization, asn, timezone
            FROM ip_geolocation 
            WHERE ip_address = ? AND last_updated > datetime('now', '-7 days')
        ''', (ip_address,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                "country": result[0],
                "region": result[1], 
                "city": result[2],
                "latitude": result[3],
                "longitude": result[4],
                "isp": result[5],
                "organization": result[6],
                "asn": result[7],
                "timezone": result[8]
            }
        return None

    def _cache_geolocation(self, ip_address: str, geo_data: Dict):
        """Cache geolocation data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO ip_geolocation 
            (ip_address, country, region, city, latitude, longitude, isp, organization, asn, timezone, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ip_address, geo_data.get("country"), geo_data.get("region"),
            geo_data.get("city"), geo_data.get("latitude"), geo_data.get("longitude"),
            geo_data.get("isp"), geo_data.get("organization"), geo_data.get("asn"),
            geo_data.get("timezone"), datetime.now()
        ))
        
        conn.commit()
        conn.close()

    def get_threat_summary(self, hours: int = 24) -> Dict:
        """Get threat summary for the specified time period."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count
            FROM threat_intel 
            WHERE last_seen > datetime('now', '-{} hours')
            GROUP BY threat_type
        '''.format(hours))
        
        threat_counts = dict(cursor.fetchall())
        
        cursor.execute('''
            SELECT AVG(confidence_score) as avg_threat_score
            FROM threat_intel 
            WHERE last_seen > datetime('now', '-{} hours')
        '''.format(hours))
        
        avg_threat = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            "time_period_hours": hours,
            "threat_breakdown": threat_counts,
            "average_threat_score": round(avg_threat, 2),
            "total_threats": sum(threat_counts.values())
        }
