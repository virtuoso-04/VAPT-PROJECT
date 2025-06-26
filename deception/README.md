# 🕷️ Honeypot File Trap System

A sophisticated honeypot system that generates realistic-looking fake files to trap and monitor unauthorized access attempts. The system uses AI-generated content to create believable decoy files and provides real-time monitoring through a modern dashboard.

## Features

- 🤖 AI-generated fake files using Hugging Face Transformers
- 📊 Real-time monitoring dashboard with Streamlit
- 🔔 Instant alerts via email and Discord
- 📝 Comprehensive access logging
- 🎯 Realistic file naming and content generation
- 🔒 Secure file access monitoring

## Tech Stack

- FastAPI for the backend API
- Streamlit for the admin dashboard
- Hugging Face Transformers for content generation
- SQLite for logging
- Plotly for data visualization
- Discord webhook and SMTP for alerts

## Prerequisites

- Python 3.10+
- pip (Python package manager)
- SMTP server credentials (for email alerts)
- Discord webhook URL (for Discord alerts)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd honeypot-file-trap
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with your configuration:
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-specific-password
DISCORD_WEBHOOK_URL=your-discord-webhook-url
ALERT_EMAIL=admin@example.com
```

## Usage

1. Start the FastAPI backend:
```bash
python main.py
```

2. In a separate terminal, start the Streamlit dashboard:
```bash
streamlit run streamlit_app.py
```

3. Access the dashboard at `http://localhost:8501`

## API Endpoints

- `POST /api/generate-files`: Generate new honeypot files
- `GET /static/{filename}`: Access a honeypot file (triggers logging)
- `GET /api/stats`: Get honeypot statistics
- `GET /api/recent-accesses`: Get recent access logs

## Dashboard Features

- Real-time metrics display
- Access timeline visualization
- IP address heatmap
- Recent access logs table
- File generation controls

## Security Considerations

- The system is designed to be deployed behind a reverse proxy
- All file access attempts are logged
- Alerts are sent for suspicious activities
- IP addresses and user agents are tracked

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Hugging Face for the Transformers library
- FastAPI for the excellent web framework
- Streamlit for the dashboard framework
- Plotly for the visualization capabilities 
