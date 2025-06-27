import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
import random
import hashlib

@dataclass
class NetworkConnection:
    """Represents a network connection."""
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    timestamp: datetime
    bytes_sent: int
    bytes_received: int
    duration: float
    flags: List[str]

class NetworkAnalyzer:
    """Analyzes network traffic patterns for honeypot interactions."""
    
    def __init__(self, db_path: str = "honeypot.db"):
        self.db_path = db_path
        self._init_network_db()
        
    def _init_network_db(self):
        """Initialize network analysis database tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                timestamp TIMESTAMP,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                duration REAL,
                flags TEXT,
                session_id TEXT,
                threat_score REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_patterns (
                id INTEGER PRIMARY KEY,
                ip_address TEXT,
                pattern_type TEXT,
                pattern_data TEXT,
                confidence_score REAL,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                occurrence_count INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_signatures (
                id INTEGER PRIMARY KEY,
                signature_name TEXT,
                pattern TEXT,
                severity TEXT,
                description TEXT,
                created_at TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Load default attack signatures
        self._load_default_signatures()

    def _load_default_signatures(self):
        """Load default attack signatures."""
        signatures = [
            {
                "name": "Port_Scan_Sequential",
                "pattern": "sequential_ports",
                "severity": "medium",
                "description": "Sequential port scanning detected"
            },
            {
                "name": "Brute_Force_SSH",
                "pattern": "ssh_brute_force",
                "severity": "high", 
                "description": "SSH brute force attack pattern"
            },
            {
                "name": "Web_Crawler_Aggressive",
                "pattern": "aggressive_crawling",
                "severity": "low",
                "description": "Aggressive web crawling behavior"
            },
            {
                "name": "Data_Exfiltration",
                "pattern": "large_outbound_transfer",
                "severity": "critical",
                "description": "Potential data exfiltration detected"
            }
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for sig in signatures:
            cursor.execute('''
                INSERT OR IGNORE INTO attack_signatures 
                (signature_name, pattern, severity, description, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (sig["name"], sig["pattern"], sig["severity"], 
                  sig["description"], datetime.now()))
        
        conn.commit()
        conn.close()

    def analyze_connection(self, source_ip: str, dest_ip: str, 
                          source_port: int, dest_port: int, 
                          protocol: str, bytes_sent: int = 0, 
                          bytes_received: int = 0) -> Dict:
        """Analyze a single network connection."""
        
        connection = NetworkConnection(
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            timestamp=datetime.now(),
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            duration=random.uniform(0.1, 5.0),  # Mock duration
            flags=self._generate_connection_flags(protocol, dest_port)
        )
        
        # Generate session ID
        session_data = f"{source_ip}:{source_port}-{dest_ip}:{dest_port}-{protocol}"
        session_id = hashlib.md5(session_data.encode()).hexdigest()[:16]
        
        # Analyze for suspicious patterns
        analysis = self._analyze_connection_patterns(connection)
        
        # Store connection
        self._store_connection(connection, session_id, analysis["threat_score"])
        
        return {
            "connection_id": session_id,
            "analysis": analysis,
            "connection_info": {
                "source": f"{source_ip}:{source_port}",
                "destination": f"{dest_ip}:{dest_port}",
                "protocol": protocol,
                "bytes_transferred": bytes_sent + bytes_received,
                "duration": connection.duration
            }
        }

    def _analyze_connection_patterns(self, connection: NetworkConnection) -> Dict:
        """Analyze connection for suspicious patterns."""
        analysis = {
            "threat_score": 0.0,
            "anomalies": [],
            "pattern_matches": [],
            "risk_factors": []
        }
        
        # Check for suspicious ports
        if connection.dest_port in [22, 23, 3389, 445, 135]:
            analysis["risk_factors"].append("High-value service port")
            analysis["threat_score"] += 0.3
        
        # Check for unusual ports
        if connection.source_port < 1024 and connection.protocol == "TCP":
            analysis["anomalies"].append("Low source port number")
            analysis["threat_score"] += 0.2
        
        # Check for large data transfers
        total_bytes = connection.bytes_sent + connection.bytes_received
        if total_bytes > 1000000:  # 1MB
            analysis["risk_factors"].append("Large data transfer")
            analysis["threat_score"] += 0.4
        
        # Check recent connections from same IP
        recent_connections = self._get_recent_connections(connection.source_ip, minutes=10)
        if len(recent_connections) > 20:
            analysis["pattern_matches"].append("High connection frequency")
            analysis["threat_score"] += 0.5
        
        # Check for port scanning patterns
        unique_ports = len(set(conn[3] for conn in recent_connections))  # dest_port
        if unique_ports > 10:
            analysis["pattern_matches"].append("Port scanning detected")
            analysis["threat_score"] += 0.7
        
        analysis["threat_score"] = min(1.0, analysis["threat_score"])
        
        return analysis

    def _generate_connection_flags(self, protocol: str, dest_port: int) -> List[str]:
        """Generate realistic connection flags."""
        flags = []
        
        if protocol == "TCP":
            flags.extend(["SYN", "ACK"])
            if dest_port in [80, 443]:
                flags.append("PSH")
            if random.random() < 0.1:
                flags.append("FIN")
        elif protocol == "UDP":
            flags.append("UDP")
        
        return flags

    def _get_recent_connections(self, ip_address: str, minutes: int = 60) -> List:
        """Get recent connections from an IP address."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, dest_ip, source_port, dest_port, protocol, timestamp
            FROM network_connections 
            WHERE source_ip = ? AND timestamp > datetime('now', '-{} minutes')
            ORDER BY timestamp DESC
        '''.format(minutes), (ip_address,))
        
        results = cursor.fetchall()
        conn.close()
        
        return results

    def _store_connection(self, connection: NetworkConnection, session_id: str, threat_score: float):
        """Store network connection in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO network_connections 
            (source_ip, dest_ip, source_port, dest_port, protocol, timestamp, 
             bytes_sent, bytes_received, duration, flags, session_id, threat_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            connection.source_ip, connection.dest_ip, connection.source_port,
            connection.dest_port, connection.protocol, connection.timestamp,
            connection.bytes_sent, connection.bytes_received, connection.duration,
            json.dumps(connection.flags), session_id, threat_score
        ))
        
        conn.commit()
        conn.close()

    def detect_attack_patterns(self, hours: int = 1) -> List[Dict]:
        """Detect attack patterns in recent network traffic."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get recent high-threat connections
        cursor.execute('''
            SELECT source_ip, COUNT(*) as connection_count, 
                   AVG(threat_score) as avg_threat_score,
                   COUNT(DISTINCT dest_port) as unique_ports,
                   SUM(bytes_sent + bytes_received) as total_bytes
            FROM network_connections 
            WHERE timestamp > datetime('now', '-{} hours')
            GROUP BY source_ip
            HAVING connection_count > 5 OR avg_threat_score > 0.5
            ORDER BY avg_threat_score DESC, connection_count DESC
        '''.format(hours), )
        
        results = cursor.fetchall()
        conn.close()
        
        attack_patterns = []
        
        for row in results:
            ip, conn_count, avg_threat, unique_ports, total_bytes = row
            
            pattern = {
                "source_ip": ip,
                "pattern_type": self._classify_attack_pattern(conn_count, unique_ports, total_bytes),
                "connection_count": conn_count,
                "average_threat_score": round(avg_threat, 2),
                "unique_ports_accessed": unique_ports,
                "total_bytes_transferred": total_bytes,
                "severity": self._calculate_pattern_severity(avg_threat, conn_count, unique_ports)
            }
            
            attack_patterns.append(pattern)
        
        return attack_patterns

    def _classify_attack_pattern(self, conn_count: int, unique_ports: int, total_bytes: int) -> str:
        """Classify the type of attack pattern."""
        if unique_ports > 20:
            return "Port Scan"
        elif conn_count > 100:
            return "DDoS/Flood"
        elif total_bytes > 10000000:  # 10MB
            return "Data Exfiltration"
        elif conn_count > 20:
            return "Brute Force"
        else:
            return "Reconnaissance"

    def _calculate_pattern_severity(self, avg_threat: float, conn_count: int, unique_ports: int) -> str:
        """Calculate severity of attack pattern."""
        score = avg_threat + (conn_count / 100) + (unique_ports / 50)
        
        if score > 2.0:
            return "Critical"
        elif score > 1.0:
            return "High"
        elif score > 0.5:
            return "Medium"
        else:
            return "Low"

    def get_network_statistics(self, hours: int = 24) -> Dict:
        """Get comprehensive network statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total connections
        cursor.execute('''
            SELECT COUNT(*) FROM network_connections 
            WHERE timestamp > datetime('now', '-{} hours')
        '''.format(hours))
        total_connections = cursor.fetchone()[0]
        
        # Unique source IPs
        cursor.execute('''
            SELECT COUNT(DISTINCT source_ip) FROM network_connections 
            WHERE timestamp > datetime('now', '-{} hours')
        '''.format(hours))
        unique_ips = cursor.fetchone()[0]
        
        # Protocol distribution
        cursor.execute('''
            SELECT protocol, COUNT(*) FROM network_connections 
            WHERE timestamp > datetime('now', '-{} hours')
            GROUP BY protocol
        '''.format(hours))
        protocol_dist = dict(cursor.fetchall())
        
        # Top target ports
        cursor.execute('''
            SELECT dest_port, COUNT(*) as count FROM network_connections 
            WHERE timestamp > datetime('now', '-{} hours')
            GROUP BY dest_port
            ORDER BY count DESC
            LIMIT 10
        '''.format(hours))
        top_ports = cursor.fetchall()
        
        # Average threat score
        cursor.execute('''
            SELECT AVG(threat_score) FROM network_connections 
            WHERE timestamp > datetime('now', '-{} hours')
        '''.format(hours))
        avg_threat = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            "time_period_hours": hours,
            "total_connections": total_connections,
            "unique_source_ips": unique_ips,
            "protocol_distribution": protocol_dist,
            "top_target_ports": [{"port": port, "count": count} for port, count in top_ports],
            "average_threat_score": round(avg_threat, 3),
            "connections_per_hour": round(total_connections / max(1, hours), 2)
        }

    def generate_network_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive network analysis report."""
        stats = self.get_network_statistics(hours)
        patterns = self.detect_attack_patterns(hours)
        
        return {
            "report_generated": datetime.now().isoformat(),
            "analysis_period": f"{hours} hours",
            "network_statistics": stats,
            "attack_patterns": patterns,
            "summary": {
                "total_threats_detected": len(patterns),
                "highest_severity": max([p["severity"] for p in patterns], default="None"),
                "most_active_attacker": patterns[0]["source_ip"] if patterns else None,
                "total_data_transferred": sum(p.get("total_bytes_transferred", 0) for p in patterns)
            }
        }
