import os
from typing import Optional, Dict
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from discord_webhook import DiscordWebhook, DiscordEmbed
from datetime import datetime

class AlertManager:
    def __init__(self, 
                 smtp_host: Optional[str] = None,
                 smtp_port: Optional[int] = None,
                 smtp_user: Optional[str] = None,
                 smtp_password: Optional[str] = None,
                 discord_webhook_url: Optional[str] = None):
        
        self.smtp_config = {
            "host": smtp_host or os.getenv("SMTP_HOST"),
            "port": smtp_port or int(os.getenv("SMTP_PORT", "587")),
            "user": smtp_user or os.getenv("SMTP_USER"),
            "password": smtp_password or os.getenv("SMTP_PASSWORD")
        }
        
        self.discord_webhook_url = discord_webhook_url or os.getenv("DISCORD_WEBHOOK_URL")
        self.alert_email = os.getenv("ALERT_EMAIL", "admin@example.com")

    async def send_email_alert(self, 
                             subject: str, 
                             message: str, 
                             severity: str = "medium") -> bool:
        """Send an email alert."""
        if not all(self.smtp_config.values()):
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.smtp_config["user"]
            msg["To"] = self.alert_email
            msg["Subject"] = f"[Honeypot Alert] {subject}"

            # Add severity color to message
            severity_colors = {
                "low": "🟢",
                "medium": "🟡",
                "high": "🔴"
            }
            color = severity_colors.get(severity.lower(), "⚪")
            
            body = f"""
            {color} Honeypot Alert
            Severity: {severity.upper()}
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            {message}
            """
            
            msg.attach(MIMEText(body, "plain"))

            async with aiosmtplib.SMTP(
                hostname=self.smtp_config["host"],
                port=self.smtp_config["port"],
                use_tls=True
            ) as smtp:
                await smtp.login(
                    self.smtp_config["user"],
                    self.smtp_config["password"]
                )
                await smtp.send_message(msg)
            return True
        except Exception as e:
            print(f"Failed to send email alert: {e}")
            return False

    def send_discord_alert(self, 
                          title: str, 
                          description: str, 
                          severity: str = "medium",
                          additional_data: Optional[Dict] = None) -> bool:
        """Send a Discord webhook alert."""
        if not self.discord_webhook_url:
            return False

        try:
            webhook = DiscordWebhook(url=self.discord_webhook_url)
            
            # Create embed
            embed = DiscordEmbed(
                title=f"🚨 Honeypot Alert: {title}",
                description=description,
                color=self._get_severity_color(severity)
            )
            
            # Add timestamp
            embed.set_timestamp()
            
            # Add additional data if provided
            if additional_data:
                for key, value in additional_data.items():
                    embed.add_embed_field(
                        name=key.replace("_", " ").title(),
                        value=str(value),
                        inline=True
                    )
            
            webhook.add_embed(embed)
            webhook.execute()
            return True
        except Exception as e:
            print(f"Failed to send Discord alert: {e}")
            return False

    def _get_severity_color(self, severity: str) -> int:
        """Get Discord embed color based on severity."""
        colors = {
            "low": 0x00ff00,    # Green
            "medium": 0xffff00,  # Yellow
            "high": 0xff0000     # Red
        }
        return colors.get(severity.lower(), 0x808080)  # Default to gray

    async def send_alert(self, 
                        title: str,
                        message: str,
                        severity: str = "medium",
                        additional_data: Optional[Dict] = None) -> Dict[str, bool]:
        """Send alerts through all configured channels."""
        results = {
            "email": await self.send_email_alert(title, message, severity),
            "discord": self.send_discord_alert(title, message, severity, additional_data)
        }
        return results 