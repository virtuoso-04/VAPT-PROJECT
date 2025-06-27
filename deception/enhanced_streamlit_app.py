import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
from datetime import datetime, timedelta
import time
import json
import subprocess
import threading
import queue
import os
from pathlib import Path
import folium
from streamlit_folium import st_folium
import numpy as np

# Configuration
API_BASE_URL = "http://localhost:8000"
REFRESH_INTERVAL = 5  # seconds
LOG_QUEUE = queue.Queue()

# Page config
st.set_page_config(
    page_title="🕷️ Advanced Honeypot Security Operations Center",
    page_icon="🕷️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS
st.markdown("""
    <style>
    .main {
        background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
        color: #e0e0e0;
    }
    .stAlert {
        background-color: rgba(46, 46, 46, 0.9);
        border-left: 4px solid #ff6b35;
    }
    .metric-card {
        background: linear-gradient(145deg, #2a2a3e, #1e1e32);
        padding: 25px;
        border-radius: 15px;
        margin: 10px 0;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .threat-critical {
        background: linear-gradient(145deg, #4a1a1a, #3d1a1a);
        border-left: 5px solid #ff2b2b;
    }
    .threat-high {
        background: linear-gradient(145deg, #4a3a1a, #3d2a1a);
        border-left: 5px solid #ff8c42;
    }
    .threat-medium {
        background: linear-gradient(145deg, #3a3a1a, #2d2d1a);
        border-left: 5px solid #ffd700;
    }
    .threat-low {
        background: linear-gradient(145deg, #1a3a1a, #1a2d1a);
        border-left: 5px solid #00ff88;
    }
    .attack-pattern {
        background: rgba(255, 107, 53, 0.1);
        padding: 15px;
        border-radius: 10px;
        margin: 8px 0;
        border-left: 4px solid #ff6b35;
    }
    .terminal {
        background-color: #000;
        color: #00ff00;
        padding: 15px;
        border-radius: 8px;
        font-family: 'Courier New', monospace;
        height: 400px;
        overflow-y: auto;
        border: 1px solid #333;
        font-size: 12px;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
    }
    .stSelectbox > div > div {
        background-color: #2a2a3e;
        color: #e0e0e0;
    }
    .stButton > button {
        background: linear-gradient(145deg, #ff6b35, #f7931e);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 0.5rem 2rem;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        background: linear-gradient(145deg, #f7931e, #ff6b35);
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(255, 107, 53, 0.4);
    }
    .status-online { color: #00ff88; }
    .status-offline { color: #ff4757; }
    .status-warning { color: #ffa502; }
    
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    .pulse { animation: pulse 2s infinite; }
    </style>
    """, unsafe_allow_html=True)

# Initialize session state
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = True
if 'attack_simulation_running' not in st.session_state:
    st.session_state.attack_simulation_running = False

def get_api_data(endpoint):
    """Get data from API with error handling."""
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", timeout=5)
        return response.json() if response.status_code == 200 else None
    except:
        return None

def format_threat_level(level):
    """Format threat level with colors."""
    colors = {
        "critical": "🔴", "high": "🟠", 
        "medium": "🟡", "low": "🟢", "unknown": "⚪"
    }
    return f"{colors.get(level, '⚪')} {level.upper()}"

def create_world_map(threat_data):
    """Create world map with threat locations."""
    if not threat_data:
        return None
    
    # Create base map
    m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
    
    # Add threat locations (mock data for demo)
    threat_locations = [
        {"lat": 55.7558, "lon": 37.6176, "country": "Russia", "threats": 15, "level": "critical"},
        {"lat": 39.9042, "lon": 116.4074, "country": "China", "threats": 23, "level": "high"},
        {"lat": 40.7128, "lon": -74.0060, "country": "USA", "threats": 8, "level": "medium"},
        {"lat": 51.5074, "lon": -0.1278, "country": "UK", "threats": 5, "level": "low"},
    ]
    
    for loc in threat_locations:
        color = {"critical": "red", "high": "orange", "medium": "yellow", "low": "green"}[loc["level"]]
        folium.CircleMarker(
            location=[loc["lat"], loc["lon"]],
            radius=loc["threats"],
            popup=f"{loc['country']}: {loc['threats']} threats ({loc['level']})",
            color=color,
            fill=True,
            fillOpacity=0.7
        ).add_to(m)
    
    return m

def main():
    # Header
    st.markdown("""
        <div style='text-align: center; padding: 20px 0;'>
            <h1 style='color: #ff6b35; font-size: 3rem; margin: 0;'>
                🕷️ Honeypot Security Operations Center
            </h1>
            <p style='color: #888; font-size: 1.2rem;'>
                Advanced Threat Detection & Deception Analytics
            </p>
        </div>
    """, unsafe_allow_html=True)

    # Sidebar Controls
    with st.sidebar:
        st.markdown("### 🎛️ Control Panel")
        
        # Auto-refresh toggle
        auto_refresh = st.toggle("🔄 Auto Refresh", value=st.session_state.auto_refresh)
        st.session_state.auto_refresh = auto_refresh
        
        if auto_refresh:
            refresh_rate = st.slider("Refresh Rate (seconds)", 1, 30, 5)
        
        st.markdown("---")
        
        # Attack Simulation
        st.markdown("### ⚔️ Attack Simulation")
        attack_type = st.selectbox(
            "Attack Type",
            ["reconnaissance", "credential_harvesting", "data_exfiltration", "random"]
        )
        
        attack_duration = st.slider("Duration (seconds)", 30, 300, 60)
        
        if st.button("🚀 Launch Attack Simulation", type="primary"):
            with st.spinner("Launching attack simulation..."):
                try:
                    response = requests.post(
                        f"{API_BASE_URL}/api/simulate-attack",
                        params={"attack_type": attack_type, "duration": attack_duration}
                    )
                    if response.status_code == 200:
                        st.success("Attack simulation launched!")
                        st.session_state.attack_simulation_running = True
                    else:
                        st.error("Failed to launch simulation")
                except:
                    st.error("API connection failed")
        
        st.markdown("---")
        
        # File Generation
        st.markdown("### 📁 Honeypot Files")
        
        if st.button("🍯 Generate Honeypot Scenario"):
            with st.spinner("Generating honeypot scenario..."):
                try:
                    response = requests.post(f"{API_BASE_URL}/api/generate-honeypot-scenario")
                    if response.status_code == 200:
                        data = response.json()
                        st.success(f"Generated scenario: {data['scenario']['name']}")
                        st.info(f"Created {len(data['generated_files'])} files")
                    else:
                        st.error("Failed to generate scenario")
                except:
                    st.error("API connection failed")
        
        file_count = st.slider("Number of files", 1, 20, 5)
        if st.button("📄 Generate Files"):
            with st.spinner("Generating files..."):
                try:
                    response = requests.post(
                        f"{API_BASE_URL}/api/generate-files",
                        params={"count": file_count}
                    )
                    if response.status_code == 200:
                        st.success(f"Generated {file_count} honeypot files!")
                    else:
                        st.error("Failed to generate files")
                except:
                    st.error("API connection failed")

    # Main Dashboard
    dashboard_data = get_api_data("/api/dashboard-data")
    
    if not dashboard_data:
        st.error("⚠️ Unable to connect to honeypot API. Make sure the backend is running.")
        return
    
    # Status Indicators
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown("""
            <div class="metric-card">
                <h3 style='color: #00ff88; margin: 0;'>🟢 System Status</h3>
                <h2 style='margin: 5px 0;'>ONLINE</h2>
                <small>All systems operational</small>
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        total_threats = dashboard_data.get('threat_intelligence', {}).get('total_threats', 0)
        st.markdown(f"""
            <div class="metric-card threat-high">
                <h3 style='color: #ff8c42; margin: 0;'>🎯 Active Threats</h3>
                <h2 style='margin: 5px 0;'>{total_threats}</h2>
                <small>Last 24 hours</small>
            </div>
        """, unsafe_allow_html=True)
    
    with col3:
        network_stats = dashboard_data.get('network_analysis', {})
        connections = network_stats.get('total_connections', 0)
        st.markdown(f"""
            <div class="metric-card">
                <h3 style='color: #4ecdc4; margin: 0;'>🌐 Connections</h3>
                <h2 style='margin: 5px 0;'>{connections}</h2>
                <small>{network_stats.get('connections_per_hour', 0)}/hour avg</small>
            </div>
        """, unsafe_allow_html=True)
    
    with col4:
        unique_ips = network_stats.get('unique_source_ips', 0)
        st.markdown(f"""
            <div class="metric-card">
                <h3 style='color: #a8e6cf; margin: 0;'>🏠 Unique IPs</h3>
                <h2 style='margin: 5px 0;'>{unique_ips}</h2>
                <small>Distinct attackers</small>
            </div>
        """, unsafe_allow_html=True)
    
    with col5:
        avg_threat = network_stats.get('average_threat_score', 0)
        threat_color = "#ff4757" if avg_threat > 0.7 else "#ffa502" if avg_threat > 0.4 else "#2ed573"
        st.markdown(f"""
            <div class="metric-card">
                <h3 style='color: {threat_color}; margin: 0;'>⚡ Threat Score</h3>
                <h2 style='margin: 5px 0;'>{avg_threat:.2f}</h2>
                <small>Average severity</small>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Main Content Tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🗺️ Threat Map", "📊 Analytics", "🚨 Live Attacks", 
        "🔍 Threat Intel", "📡 Network", "📋 Activity Log"
    ])

    with tab1:
        st.markdown("### 🗺️ Global Threat Activity Map")
        
        # Create and display world map
        threat_map = create_world_map(dashboard_data)
        if threat_map:
            st_folium(threat_map, width=1200, height=500)
        
        # Regional threat breakdown
        col1, col2 = st.columns(2)
        
        with col1:
            # Mock regional data
            regions = ["Russia", "China", "North Korea", "Iran", "Unknown"]
            threat_counts = [23, 18, 12, 8, 15]
            
            fig = px.pie(
                values=threat_counts, 
                names=regions,
                title="Threats by Region",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Threat severity distribution
            severities = ["Critical", "High", "Medium", "Low"]
            severity_counts = [5, 12, 28, 31]
            
            fig = px.bar(
                x=severities, y=severity_counts,
                title="Threat Severity Distribution",
                color=severities,
                color_discrete_map={
                    "Critical": "#ff4757",
                    "High": "#ff6b35", 
                    "Medium": "#ffa502",
                    "Low": "#2ed573"
                }
            )
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white',
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.markdown("### 📊 Advanced Analytics Dashboard")
        
        # Time series analysis
        col1, col2 = st.columns(2)
        
        with col1:
            # Generate mock time series data
            dates = pd.date_range(end=datetime.now(), periods=24, freq='H')
            attack_counts = np.random.poisson(5, 24) + np.random.randint(0, 10, 24)
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=dates, y=attack_counts,
                mode='lines+markers',
                name='Attack Attempts',
                line=dict(color='#ff6b35', width=3),
                marker=dict(size=6)
            ))
            
            fig.update_layout(
                title="Attack Attempts (24 Hours)",
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white',
                xaxis_title="Time",
                yaxis_title="Attempts"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Attack types distribution
            attack_types = ["Port Scan", "Brute Force", "Data Exfiltration", "Reconnaissance", "DDoS"]
            type_counts = [15, 12, 8, 20, 5]
            
            fig = px.bar(
                x=type_counts, y=attack_types,
                orientation='h',
                title="Attack Types (24h)",
                color=type_counts,
                color_continuous_scale="Reds"
            )
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white'
            )
            st.plotly_chart(fig, use_container_width=True)

    with tab3:
        st.markdown("### 🚨 Live Attack Detection")
        
        # Recent attack patterns
        attack_patterns = dashboard_data.get('recent_attack_patterns', [])
        
        if attack_patterns:
            for pattern in attack_patterns[:5]:
                severity_class = f"threat-{pattern.get('severity', 'low').lower()}"
                st.markdown(f"""
                    <div class="attack-pattern {severity_class}">
                        <h4 style='margin: 0 0 10px 0;'>
                            {format_threat_level(pattern.get('severity', 'unknown'))} 
                            {pattern.get('pattern_type', 'Unknown Attack')}
                        </h4>
                        <p><strong>Source:</strong> {pattern.get('source_ip', 'Unknown')}</p>
                        <p><strong>Connections:</strong> {pattern.get('connection_count', 0)} | 
                           <strong>Ports:</strong> {pattern.get('unique_ports_accessed', 0)} | 
                           <strong>Data:</strong> {pattern.get('total_bytes_transferred', 0):,} bytes</p>
                        <p><strong>Threat Score:</strong> {pattern.get('average_threat_score', 0)}</p>
                    </div>
                """, unsafe_allow_html=True)
        else:
            st.info("🛡️ No active attack patterns detected")
        
        # Live activity terminal
        st.markdown("### 💻 Live Activity Feed")
        st.markdown('<div class="terminal" id="terminal">', unsafe_allow_html=True)
        
        # Mock terminal output
        terminal_logs = [
            "[2025-06-26 14:32:15] 🔴 CRITICAL: Malicious IP 45.142.212.33 accessed financial_report_q4.pdf",
            "[2025-06-26 14:31:58] 🟠 HIGH: Port scan detected from 198.51.100.42 (22 ports scanned)",
            "[2025-06-26 14:31:42] 🟡 MEDIUM: Suspicious user agent detected: sqlmap/1.6.2",
            "[2025-06-26 14:31:28] 🔴 CRITICAL: Data exfiltration attempt - 2.3MB transferred",
            "[2025-06-26 14:31:15] 🟢 INFO: Honeypot file employee_data_2025.xlsx accessed",
            "[2025-06-26 14:30:59] 🟠 HIGH: Brute force attempt on SSH (15 attempts)",
            "[2025-06-26 14:30:41] 🟡 MEDIUM: Tor exit node 185.220.101.42 detected",
            "[2025-06-26 14:30:23] 🔴 CRITICAL: Botnet member 103.224.182.245 active"
        ]
        
        for log in terminal_logs:
            st.code(log, language=None)
        
        st.markdown('</div>', unsafe_allow_html=True)

    with tab4:
        st.markdown("### 🔍 Threat Intelligence Analysis")
        
        # IP Analysis Tool
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.markdown("#### 🔍 IP Analyzer")
            test_ip = st.text_input("Enter IP Address", value="45.142.212.33")
            
            if st.button("🔍 Analyze IP"):
                with st.spinner("Analyzing IP..."):
                    ip_analysis = get_api_data(f"/api/threat-intel/{test_ip}")
                    
                    if ip_analysis:
                        st.session_state.ip_analysis = ip_analysis
        
        with col2:
            if 'ip_analysis' in st.session_state:
                analysis = st.session_state.ip_analysis
                
                st.markdown(f"#### Analysis Results for {analysis['ip_address']}")
                
                # Threat level badge
                threat_level = analysis.get('threat_level', 'unknown')
                reputation = analysis.get('reputation_score', 0)
                
                st.markdown(f"""
                    <div class="metric-card threat-{threat_level}">
                        <h3>{format_threat_level(threat_level)}</h3>
                        <p><strong>Reputation Score:</strong> {reputation}/100</p>
                        <p><strong>Location:</strong> {analysis.get('geolocation', {}).get('country', 'Unknown')}</p>
                        <p><strong>ISP:</strong> {analysis.get('geolocation', {}).get('isp', 'Unknown')}</p>
                    </div>
                """, unsafe_allow_html=True)
                
                # Threat indicators
                if analysis.get('threat_indicators'):
                    st.markdown("**Threat Indicators:**")
                    for indicator in analysis['threat_indicators']:
                        confidence = indicator.get('confidence', 0) * 100
                        st.markdown(f"- **{indicator.get('type', 'Unknown')}** ({confidence:.0f}% confidence)")

    with tab5:
        st.markdown("### 📡 Network Traffic Analysis")
        
        network_data = dashboard_data.get('network_analysis', {})
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Total Connections", 
                network_data.get('total_connections', 0),
                delta="+12 from last hour"
            )
        
        with col2:
            st.metric(
                "Unique Source IPs", 
                network_data.get('unique_source_ips', 0),
                delta="+3 new attackers"
            )
        
        with col3:
            st.metric(
                "Avg Threat Score", 
                f"{network_data.get('average_threat_score', 0):.3f}",
                delta="+0.05 increase"
            )
        
        # Protocol distribution
        protocol_dist = network_data.get('protocol_distribution', {})
        if protocol_dist:
            fig = px.pie(
                values=list(protocol_dist.values()),
                names=list(protocol_dist.keys()),
                title="Protocol Distribution"
            )
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Top target ports
        top_ports = network_data.get('top_target_ports', [])
        if top_ports:
            ports_df = pd.DataFrame(top_ports)
            fig = px.bar(
                ports_df, x='port', y='count',
                title="Most Targeted Ports",
                labels={'port': 'Port Number', 'count': 'Connection Attempts'}
            )
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white'
            )
            st.plotly_chart(fig, use_container_width=True)

    with tab6:
        st.markdown("### 📋 Detailed Activity Log")
        
        # Activity filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            log_limit = st.selectbox("Show entries", [10, 25, 50, 100], index=1)
        
        with col2:
            severity_filter = st.selectbox(
                "Severity Filter", 
                ["All", "Critical", "High", "Medium", "Low"]
            )
        
        with col3:
            time_filter = st.selectbox(
                "Time Range",
                ["Last Hour", "Last 6 Hours", "Last 24 Hours", "Last Week"]
            )
        
        # Mock activity log data
        activity_data = []
        for i in range(log_limit):
            timestamp = datetime.now() - timedelta(minutes=i*5)
            severities = ["Critical", "High", "Medium", "Low"]
            events = [
                "File Access", "Port Scan", "Brute Force", "Data Transfer", 
                "Reconnaissance", "Malware Drop", "Command Injection"
            ]
            
            activity_data.append({
                "Timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Severity": np.random.choice(severities),
                "Event": np.random.choice(events),
                "Source IP": f"{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
                "Details": f"Target: honeypot_file_{i}.pdf | Size: {np.random.randint(100,5000)}KB"
            })
        
        df = pd.DataFrame(activity_data)
        
        # Apply severity filter
        if severity_filter != "All":
            df = df[df['Severity'] == severity_filter]
        
        # Color coding for severity
        def color_severity(val):
            colors = {
                "Critical": "background-color: #4a1a1a; color: #ff6b6b;",
                "High": "background-color: #4a3a1a; color: #ff8c42;",
                "Medium": "background-color: #3a3a1a; color: #ffd700;",
                "Low": "background-color: #1a3a1a; color: #00ff88;"
            }
            return colors.get(val, "")
        
        # Display styled dataframe
        styled_df = df.style.applymap(color_severity, subset=['Severity'])
        st.dataframe(styled_df, use_container_width=True, height=400)
        
        # Export options
        if st.button("📥 Export Log Data"):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"honeypot_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

    # Auto-refresh mechanism
    if st.session_state.auto_refresh:
        time.sleep(1)  # Brief pause
        st.rerun()

if __name__ == "__main__":
    main()
