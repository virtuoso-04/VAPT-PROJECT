import sqlite3
import datetime
from pathlib import Path
from typing import Optional, Dict, Any

class DatabaseLogger:
    def __init__(self, db_path: str = "honeypot.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database with required tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create files table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            content_type TEXT,
            size INTEGER,
            is_accessed BOOLEAN DEFAULT FALSE
        )
        ''')

        # Create access_logs table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files (id)
        )
        ''')

        conn.commit()
        conn.close()

    def log_file_creation(self, filename: str, content_type: str, size: int) -> int:
        """Log a newly created honeypot file."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO files (filename, content_type, size)
        VALUES (?, ?, ?)
        ''', (filename, content_type, size))
        
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return file_id

    def log_file_access(self, file_id: int, ip_address: str, user_agent: Optional[str] = None) -> None:
        """Log when a honeypot file is accessed."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO access_logs (file_id, ip_address, user_agent)
        VALUES (?, ?, ?)
        ''', (file_id, ip_address, user_agent))
        
        cursor.execute('''
        UPDATE files SET is_accessed = TRUE WHERE id = ?
        ''', (file_id,))
        
        conn.commit()
        conn.close()

    def get_access_stats(self) -> Dict[str, Any]:
        """Get statistics about file accesses."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get total accesses
        cursor.execute('SELECT COUNT(*) FROM access_logs')
        total_accesses = cursor.fetchone()[0]
        
        # Get unique IPs
        cursor.execute('SELECT COUNT(DISTINCT ip_address) FROM access_logs')
        unique_ips = cursor.fetchone()[0]
        
        # Get most accessed files
        cursor.execute('''
        SELECT f.filename, COUNT(a.id) as access_count
        FROM files f
        JOIN access_logs a ON f.id = a.file_id
        GROUP BY f.id
        ORDER BY access_count DESC
        LIMIT 5
        ''')
        most_accessed = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_accesses': total_accesses,
            'unique_ips': unique_ips,
            'most_accessed': most_accessed
        }

    def get_recent_accesses(self, limit: int = 10) -> list:
        """Get recent file access logs."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT a.timestamp, f.filename, a.ip_address, a.user_agent
        FROM access_logs a
        JOIN files f ON a.file_id = f.id
        ORDER BY a.timestamp DESC
        LIMIT ?
        ''', (limit,))
        
        recent = cursor.fetchall()
        conn.close()
        return recent 