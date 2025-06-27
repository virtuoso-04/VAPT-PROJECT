import asyncio
import random
import requests
from datetime import datetime, timedelta
from typing import List, Dict
import json
from pathlib import Path

class AttackSimulator:
    """Simulates various types of attacks for demonstration purposes."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.attack_patterns = {
            "reconnaissance": [
                "/static/financial_report_q4.pdf",
                "/static/employee_data_2025.xlsx",
                "/static/api_docs_v2.json",
                "/static/security_audit_final.txt"
            ],
            "credential_harvesting": [
                "/static/passwords.txt",
                "/static/config.json",
                "/static/.env",
                "/static/database_backup.sql"
            ],
            "data_exfiltration": [
                "/static/customer_database.csv",
                "/static/financial_records_2025.pdf",
                "/static/employee_records.xlsx",
                "/static/profit_loss_q1.pdf"
            ]
        }
        
        self.attack_sources = [
            {"ip": "45.142.212.33", "location": "Russia", "isp": "Unknown"},
            {"ip": "198.51.100.42", "location": "China", "isp": "Alibaba Cloud"},
            {"ip": "203.0.113.195", "location": "North Korea", "isp": "STAR-KP"},
            {"ip": "192.0.2.146", "location": "Iran", "isp": "AS48434"},
            {"ip": "185.220.101.42", "location": "Germany", "isp": "Tor Network"},
        ]
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "curl/7.68.0",
            "Wget/1.20.3",
            "python-requests/2.28.1",
            "Nmap Scripting Engine",
            "sqlmap/1.6.2",
            "Nikto/2.1.6"
        ]

    async def simulate_attack_wave(self, attack_type: str = "random", duration: int = 60):
        """Simulate a wave of attacks over a specified duration."""
        if attack_type == "random":
            attack_type = random.choice(list(self.attack_patterns.keys()))
        
        files_to_access = self.attack_patterns.get(attack_type, [])
        end_time = datetime.now() + timedelta(seconds=duration)
        
        attack_log = []
        
        while datetime.now() < end_time:
            # Random delay between attacks
            await asyncio.sleep(random.uniform(1, 5))
            
            # Select random file and attacker
            file_path = random.choice(files_to_access)
            attacker = random.choice(self.attack_sources)
            user_agent = random.choice(self.user_agents)
            
            # Simulate the attack
            attack_info = await self._simulate_single_attack(file_path, attacker, user_agent)
            attack_log.append(attack_info)
            
        return {
            "attack_type": attack_type,
            "duration": duration,
            "total_attempts": len(attack_log),
            "attacks": attack_log
        }

    async def _simulate_single_attack(self, file_path: str, attacker: Dict, user_agent: str):
        """Simulate a single attack attempt."""
        try:
            headers = {
                "User-Agent": user_agent,
                "X-Forwarded-For": attacker["ip"],
                "X-Real-IP": attacker["ip"]
            }
            
            response = requests.get(f"{self.base_url}{file_path}", headers=headers, timeout=5)
            
            return {
                "timestamp": datetime.now().isoformat(),
                "file_path": file_path,
                "attacker_ip": attacker["ip"],
                "location": attacker["location"],
                "user_agent": user_agent,
                "status_code": response.status_code,
                "success": response.status_code == 200
            }
        except Exception as e:
            return {
                "timestamp": datetime.now().isoformat(),
                "file_path": file_path,
                "attacker_ip": attacker["ip"],
                "location": attacker["location"],
                "user_agent": user_agent,
                "error": str(e),
                "success": False
            }

    def generate_demo_scenario(self) -> Dict:
        """Generate a realistic demo scenario description."""
        scenarios = [
            {
                "name": "APT Group Reconnaissance",
                "description": "Advanced Persistent Threat group scanning for financial documents",
                "attack_type": "reconnaissance",
                "duration": 120,
                "sophistication": "high"
            },
            {
                "name": "Ransomware Gang Data Hunt",
                "description": "Cybercriminals searching for valuable data to encrypt",
                "attack_type": "data_exfiltration",
                "duration": 180,
                "sophistication": "medium"
            },
            {
                "name": "Script Kiddie Exploration",
                "description": "Amateur attacker using automated tools",
                "attack_type": "credential_harvesting",
                "duration": 90,
                "sophistication": "low"
            }
        ]
        return random.choice(scenarios)
