from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
import uvicorn
from typing import List, Dict
import os
from datetime import datetime

from file_generator import FakeFileGenerator
from logger import DatabaseLogger
from alert import AlertManager

app = FastAPI(title="Honeypot File Trap System")

# Initialize components
file_generator = FakeFileGenerator()
logger = DatabaseLogger()
alert_manager = AlertManager()

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
        return files
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/static/{filename}")
async def serve_file(filename: str, request: Request):
    """Serve a static file and log access."""
    file_path = static_dir / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    # Log the access
    logger.log_file_access(
        file_id=1,  # You'll need to implement a way to get the file_id
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent")
    )
    
    # Send alert
    await alert_manager.send_alert(
        title="Honeypot File Accessed",
        message=f"File '{filename}' was accessed",
        severity="high",
        additional_data={
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent"),
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

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 