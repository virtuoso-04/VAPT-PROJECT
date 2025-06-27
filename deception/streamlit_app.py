import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
from datetime import datetime, timedelta
import time
import json
import subprocess
import threading
import queue
import os
from pathlib import Path

# Configuration
API_BASE_URL = "http://localhost:8000"
REFRESH_INTERVAL = 5  # seconds
LOG_QUEUE = queue.Queue()

# Page config
st.set_page_config(
    page_title="Honeypot Monitor",
    page_icon="🕷️",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        background-color: #1E1E1E;
        color: #FFFFFF;
    }
    .stAlert {
        background-color: #2E2E2E;
    }
    .metric-card {
        background-color: #2E2E2E;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    .terminal {
        background-color: #1E1E1E;
        color: #00FF00;
        padding: 10px;
        border-radius: 5px;
        font-family: 'Courier New', monospace;
        height: 300px;
        overflow-y: auto;
    }
    .log-entry {
        margin: 2px 0;
        padding: 2px 5px;
    }
    .log-info { color: #00FF00; }
    .log-warning { color: #FFFF00; }
    .log-error { color: #FF0000; }
    .file-card {
        background-color: #2E2E2E;
        padding: 15px;
        border-radius: 8px;
        margin: 5px 0;
    }
    .status-indicator {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 5px;
    }
    .status-active { background-color: #00FF00; }
    .status-inactive { background-color: #FF0000; }
    </style>
    """, unsafe_allow_html=True)

def get_system_status():
    """Get system status information."""
    try:
        # Check if FastAPI server is running
        response = requests.get(f"{API_BASE_URL}/api/stats")
        api_status = response.status_code == 200
        
        # Get static directory size
        static_dir = Path("app/static")
        total_size = sum(f.stat().st_size for f in static_dir.glob('**/*') if f.is_file())
        
        # Get number of files
        file_count = len(list(static_dir.glob('*')))
        
        return {
            "api_status": api_status,
            "total_size": total_size,
            "file_count": file_count,
            "last_check": datetime.now()
        }
    except:
        return {
            "api_status": False,
            "total_size": 0,
            "file_count": 0,
            "last_check": datetime.now()
        }

def get_file_list():
    """Get list of honeypot files."""
    static_dir = Path("app/static")
    files = []
    for file in static_dir.glob('*'):
        files.append({
            "name": file.name,
            "size": file.stat().st_size,
            "created": datetime.fromtimestamp(file.stat().st_ctime),
            "accessed": datetime.fromtimestamp(file.stat().st_atime)
        })
    return files

def delete_file(filename):
    """Delete a honeypot file."""
    try:
        file_path = Path("app/static") / filename
        if file_path.exists():
            file_path.unlink()
            return True
    except Exception as e:
        st.error(f"Error deleting file: {e}")
    return False

def log_reader():
    """Read logs from the FastAPI process and add them to the queue."""
    process = subprocess.Popen(
        ['python', 'main.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        bufsize=1
    )
    
    while True:
        output = process.stdout.readline()
        if output:
            LOG_QUEUE.put(('info', output.strip()))
        error = process.stderr.readline()
        if error:
            LOG_QUEUE.put(('error', error.strip()))

def fetch_data():
    """Fetch data from the API."""
    try:
        stats = requests.get(f"{API_BASE_URL}/api/stats").json()
        recent = requests.get(f"{API_BASE_URL}/api/recent-accesses").json()
        return stats, recent
    except Exception as e:
        st.error(f"Error fetching data: {e}")
        return None, None

def create_metrics_row(stats):
    """Create a row of metric cards."""
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            label="Total Access Attempts",
            value=stats["total_accesses"],
            delta=None
        )
    
    with col2:
        st.metric(
            label="Unique IP Addresses",
            value=stats["unique_ips"],
            delta=None
        )
    
    with col3:
        st.metric(
            label="Most Accessed File",
            value=stats["most_accessed"][0][0] if stats["most_accessed"] else "None",
            delta=None
        )

def create_access_timeline(recent_accesses):
    """Create a timeline of recent accesses."""
    if not recent_accesses:
        return
    
    df = pd.DataFrame(recent_accesses, columns=["timestamp", "filename", "ip_address", "user_agent"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    
    fig = px.timeline(
        df,
        x_start="timestamp",
        y="filename",
        color="ip_address",
        title="Recent File Access Timeline"
    )
    
    fig.update_layout(
        template="plotly_dark",
        xaxis_title="Time",
        yaxis_title="File",
        showlegend=True
    )
    
    st.plotly_chart(fig, use_container_width=True)

def create_ip_heatmap(recent_accesses):
    """Create a heatmap of IP addresses and accessed files."""
    if not recent_accesses:
        return
    
    df = pd.DataFrame(recent_accesses, columns=["timestamp", "filename", "ip_address", "user_agent"])
    pivot_table = pd.pivot_table(
        df,
        values="timestamp",
        index="ip_address",
        columns="filename",
        aggfunc="count",
        fill_value=0
    )
    
    fig = go.Figure(data=go.Heatmap(
        z=pivot_table.values,
        x=pivot_table.columns,
        y=pivot_table.index,
        colorscale="Viridis"
    ))
    
    fig.update_layout(
        title="IP Address vs File Access Heatmap",
        xaxis_title="File",
        yaxis_title="IP Address",
        template="plotly_dark"
    )
    
    st.plotly_chart(fig, use_container_width=True)

def display_terminal_logs():
    """Display terminal logs in a scrollable container."""
    st.subheader("Terminal Logs")
    log_container = st.empty()
    
    logs = []
    while not LOG_QUEUE.empty():
        log_type, message = LOG_QUEUE.get_nowait()
        logs.append((log_type, message))
    
    if logs:
        log_html = '<div class="terminal">'
        for log_type, message in logs[-100:]:  # Show last 100 logs
            log_class = f"log-{log_type}"
            log_html += f'<div class="log-entry {log_class}">{message}</div>'
        log_html += '</div>'
        log_container.markdown(log_html, unsafe_allow_html=True)

def display_system_status():
    """Display system status information."""
    st.subheader("System Status")
    status = get_system_status()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        status_color = "status-active" if status["api_status"] else "status-inactive"
        st.markdown(f"""
            <div class="file-card">
                <h4>API Status</h4>
                <div class="status-indicator {status_color}"></div>
                {status["api_status"] and "Active" or "Inactive"}
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
            <div class="file-card">
                <h4>Total Storage</h4>
                {status["total_size"] / 1024:.2f} KB
            </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
            <div class="file-card">
                <h4>File Count</h4>
                {status["file_count"]} files
            </div>
        """, unsafe_allow_html=True)

def display_file_management():
    """Display file management interface."""
    st.subheader("File Management")
    
    # File generation controls
    col1, col2 = st.columns([1, 2])
    with col1:
        if st.button("Generate New Files", key="generate_files_btn"):
            try:
                response = requests.post(f"{API_BASE_URL}/api/generate-files")
                if response.status_code == 200:
                    st.success("Generated new honeypot files!")
                else:
                    st.error("Failed to generate files")
            except Exception as e:
                st.error(f"Error: {e}")
    
    # File list
    files = get_file_list()
    if files:
        for file in files:
            col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
            with col1:
                st.markdown(f"""
                    <div class="file-card">
                        <strong>{file['name']}</strong><br>
                        Created: {file['created'].strftime('%Y-%m-%d %H:%M:%S')}
                    </div>
                """, unsafe_allow_html=True)
            with col2:
                st.text(f"{file['size'] / 1024:.1f} KB")
            with col3:
                st.text(file['accessed'].strftime('%H:%M:%S'))
            with col4:
                if st.button("Delete", key=f"del_{file['name']}"):
                    if delete_file(file['name']):
                        st.success(f"Deleted {file['name']}")
                        time.sleep(1)
                        st.experimental_rerun()

def main():
    st.title("🕷️ Honeypot Monitor Dashboard")
    
    # Start log reader in a separate thread
    log_thread = threading.Thread(target=log_reader, daemon=True)
    log_thread.start()
    
    # Sidebar
    st.sidebar.title("Controls")
    st.sidebar.markdown("### Quick Actions")
    if st.sidebar.button("Generate New Honeypot Files", key="sidebar_generate_btn"):
        try:
            response = requests.post(f"{API_BASE_URL}/api/generate-files")
            if response.status_code == 200:
                st.sidebar.success("Generated new honeypot files!")
            else:
                st.sidebar.error("Failed to generate files")
        except Exception as e:
            st.sidebar.error(f"Error: {e}")
    
    # Main content
    placeholder = st.empty()
    
    while True:
        with placeholder.container():
            # System Status
            display_system_status()
            
            # File Management
            display_file_management()
            
            # Fetch and display data
            stats, recent = fetch_data()
            
            if stats and recent:
                create_metrics_row(stats)
                
                # Create tabs for different visualizations
                tab1, tab2, tab3 = st.tabs(["Access Timeline", "IP Heatmap", "Terminal Logs"])
                
                with tab1:
                    create_access_timeline(recent)
                
                with tab2:
                    create_ip_heatmap(recent)
                
                with tab3:
                    display_terminal_logs()
                
                # Recent accesses table
                st.subheader("Recent Access Logs")
                df = pd.DataFrame(recent, columns=["Timestamp", "File", "IP Address", "User Agent"])
                st.dataframe(df, use_container_width=True)
            
        time.sleep(REFRESH_INTERVAL)

if __name__ == "__main__":
    main() 