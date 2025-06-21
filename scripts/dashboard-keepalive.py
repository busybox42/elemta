#!/usr/bin/env python3
"""
Dashboard Keep-Alive Script
Generates light periodic traffic to keep Grafana dashboards populated with fresh data
"""

import smtplib
import time
import random
import signal
import sys
from email.mime.text import MIMEText
from datetime import datetime

class DashboardKeepAlive:
    """Generate periodic light traffic to keep dashboards populated"""
    
    def __init__(self):
        self.smtp_host = 'localhost'
        self.smtp_port = 2525
        self.running = True
        self.message_count = 0
        
        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Test data
        self.domains = ['example.com', 'test.org', 'demo.net']
        self.users = ['alice', 'bob', 'charlie', 'diana']
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\n🛑 Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def log(self, message: str):
        """Simple logging with timestamps"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def send_keepalive_message(self):
        """Send a single keep-alive message"""
        try:
            from_addr = f"{random.choice(self.users)}@{random.choice(self.domains)}"
            to_addr = f"{random.choice(self.users)}@{random.choice(self.domains)}"
            
            msg = MIMEText(f"Keep-alive message #{self.message_count} at {datetime.now()}")
            msg['Subject'] = f"Dashboard Keep-Alive #{self.message_count}"
            msg['From'] = from_addr
            msg['To'] = to_addr
            
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.send_message(msg)
            server.quit()
            
            self.message_count += 1
            return True
            
        except Exception as e:
            self.log(f"❌ Failed to send keep-alive message: {e}")
            return False
    
    def run(self, interval: int = 30):
        """Run keep-alive loop with specified interval (seconds)"""
        self.log(f"🚀 Starting dashboard keep-alive (interval: {interval}s)")
        self.log("Press Ctrl+C to stop gracefully")
        
        last_status_time = time.time()
        status_interval = 300  # Status update every 5 minutes
        
        while self.running:
            try:
                # Send keep-alive message
                success = self.send_keepalive_message()
                
                # Periodic status update
                current_time = time.time()
                if current_time - last_status_time >= status_interval:
                    self.log(f"📊 Status: {self.message_count} keep-alive messages sent")
                    last_status_time = current_time
                
                # Wait for next interval
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.log(f"❌ Keep-alive loop error: {e}")
                time.sleep(10)  # Wait before retrying
        
        self.log(f"✅ Keep-alive stopped. Total messages sent: {self.message_count}")

def main():
    """Main execution function"""
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("""
Dashboard Keep-Alive Script

Generates light periodic SMTP traffic to keep Grafana dashboards populated with fresh data.

Usage:
  python3 scripts/dashboard-keepalive.py [interval_seconds]

Arguments:
  interval_seconds    Time between messages (default: 30 seconds)

Examples:
  python3 scripts/dashboard-keepalive.py          # Send message every 30 seconds
  python3 scripts/dashboard-keepalive.py 60       # Send message every minute
  python3 scripts/dashboard-keepalive.py 10       # Send message every 10 seconds

This script runs continuously until stopped with Ctrl+C.
It's designed to be lightweight and non-disruptive.
        """)
        return
    
    # Get interval from command line or use default
    interval = 30
    if len(sys.argv) > 1:
        try:
            interval = int(sys.argv[1])
            if interval < 5:
                print("❌ Error: Minimum interval is 5 seconds")
                return
        except ValueError:
            print("❌ Error: Interval must be a number")
            return
    
    keepalive = DashboardKeepAlive()
    keepalive.run(interval)

if __name__ == "__main__":
    main() 