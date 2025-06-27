from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
import uvicorn
from typing import List, Dict
import os
from datetime import datetime
import random
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from file_generator import FakeFileGenerator
from logger import DatabaseLogger
from alert import AlertManager
from attack_simulator import AttackSimulator
from threat_intelligence import ThreatIntelligence
from network_analyzer import NetworkAnalyzer

app = FastAPI(title="Honeypot File Trap System")

# Initialize components
file_generator = FakeFileGenerator()
logger = DatabaseLogger()
alert_manager = AlertManager()
attack_simulator = AttackSimulator()
threat_intel = ThreatIntelligence()
network_analyzer = NetworkAnalyzer()

# Mount static files directory
static_dir = Path("app/static")
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.post("/api/generate-files")
async def generate_files(count: int = 5) -> List[Dict]:
    """Generate fake honeypot files."""
    try:
        files = file_generator.generate_multiple_files(count)
        for file_info in files:
            logger.log_file_creation(
                file_info["filename"],
                file_info["content_type"],
                file_info["size"]
            )
        
        # Send email alert for new file generation
        if files:
            file_list = "\n".join([f"- {file['filename']} ({file['category']}) - {file['size']} bytes" for file in files])
            alert_message = f"""
New honeypot files have been generated:

{file_list}

Total files generated: {len(files)}
Generation time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

These files are now active and ready to trap potential attackers.
"""
            
            await alert_manager.send_email_alert(
                subject=f"New Honeypot Files Generated ({len(files)} files)",
                message=alert_message,
                severity="low"
            )
        
        return files
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/static/{filename}")
async def serve_file(filename: str, request: Request):
    """Serve a static file and log access."""
    file_path = static_dir / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    # Get client information
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    x_forwarded_for = request.headers.get("x-forwarded-for")
    x_real_ip = request.headers.get("x-real-ip")
    
    # Use forwarded IP if available (for proxy/load balancer scenarios)
    actual_ip = x_real_ip or x_forwarded_for or client_ip
    
    # Analyze the IP for threats
    threat_analysis = threat_intel.analyze_ip(actual_ip)
    
    # Analyze network connection
    network_analysis = network_analyzer.analyze_connection(
        source_ip=actual_ip,
        dest_ip="127.0.0.1",  # Honeypot server IP
        source_port=random.randint(1024, 65535),
        dest_port=8000,
        protocol="HTTP",
        bytes_sent=len(request.headers),
        bytes_received=file_path.stat().st_size if file_path.exists() else 0
    )
    
    # Log the access
    logger.log_file_access(
        file_id=1,  # You'll need to implement a way to get the file_id
        ip_address=actual_ip,
        user_agent=user_agent
    )
    
    # Determine alert severity based on threat analysis
    severity = "low"
    if threat_analysis["threat_level"] == "critical":
        severity = "critical"
    elif threat_analysis["threat_level"] == "high":
        severity = "high"
    elif threat_analysis["reputation_score"] < 50:
        severity = "medium"
    
    # Send alert
    await alert_manager.send_alert(
        title=f"Honeypot File Accessed - {severity.upper()} THREAT",
        message=f"File '{filename}' was accessed by potentially malicious actor",
        severity=severity,
        additional_data={
            "ip_address": actual_ip,
            "user_agent": user_agent,
            "filename": filename,
            "threat_level": threat_analysis["threat_level"],
            "reputation_score": threat_analysis["reputation_score"],
            "geolocation": threat_analysis["geolocation"],
            "threat_indicators": threat_analysis["threat_indicators"],
            "network_analysis": network_analysis,
            "timestamp": datetime.now().isoformat()
        }
    )
    
    return FileResponse(file_path)

@app.get("/api/stats")
async def get_stats():
    """Get honeypot statistics."""
    return logger.get_access_stats()

@app.get("/api/recent-accesses")
async def get_recent_accesses(limit: int = 10):
    """Get recent file access logs."""
    return logger.get_recent_accesses(limit)

# New enhanced endpoints
@app.post("/api/simulate-attack")
async def simulate_attack(attack_type: str = "random", duration: int = 60):
    """Simulate an attack for demonstration purposes."""
    try:
        result = await attack_simulator.simulate_attack_wave(attack_type, duration)
        return {
            "status": "success",
            "simulation_result": result,
            "message": f"Simulated {attack_type} attack for {duration} seconds"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/threat-intel/{ip_address}")
async def analyze_ip_threat(ip_address: str):
    """Analyze an IP address for threat intelligence."""
    try:
        analysis = threat_intel.analyze_ip(ip_address)
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/network-analysis")
async def get_network_analysis(hours: int = 24):
    """Get network traffic analysis."""
    try:
        analysis = network_analyzer.get_network_statistics(hours)
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/attack-patterns")
async def get_attack_patterns(hours: int = 1):
    """Get detected attack patterns."""
    try:
        patterns = network_analyzer.detect_attack_patterns(hours)
        return {
            "patterns": patterns,
            "count": len(patterns),
            "analysis_period": f"{hours} hours"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/threat-summary")
async def get_threat_summary(hours: int = 24):
    """Get comprehensive threat summary."""
    try:
        summary = threat_intel.get_threat_summary(hours)
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/generate-honeypot-scenario")
async def generate_honeypot_scenario():
    """Generate a realistic honeypot scenario for demonstration."""
    try:
        scenario = attack_simulator.generate_demo_scenario()
        # Generate appropriate files for the scenario
        file_count = random.randint(5, 15)
        files = file_generator.generate_multiple_files(file_count)
        
        return {
            "scenario": scenario,
            "generated_files": files,
            "message": f"Generated {file_count} honeypot files for {scenario['name']} scenario"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard-data")
async def get_dashboard_data():
    """Get comprehensive dashboard data."""
    try:
        stats = logger.get_access_stats()
        threat_summary = threat_intel.get_threat_summary(24)
        network_stats = network_analyzer.get_network_statistics(24)
        attack_patterns = network_analyzer.detect_attack_patterns(1)
        
        return {
            "file_access_stats": stats,
            "threat_intelligence": threat_summary,
            "network_analysis": network_stats,
            "recent_attack_patterns": attack_patterns[:5],
            "last_updated": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)