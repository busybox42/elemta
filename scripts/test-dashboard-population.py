#!/usr/bin/env python3
"""
Dashboard Population Test Script
Generates comprehensive test traffic to populate all Elemta Grafana dashboards
"""

import smtplib
import socket
import threading
import time
import random
import sys
import requests
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple

class DashboardPopulator:
    """Generate test traffic to populate all Grafana dashboards"""
    
    def __init__(self):
        self.smtp_host = 'localhost'
        self.smtp_port = 2525
        self.metrics_url = 'http://localhost:8080/metrics'
        self.prometheus_url = 'http://localhost:9090'
        self.grafana_url = 'http://localhost:3000'
        
        # Test data
        self.test_domains = ['example.com', 'test.org', 'demo.net', 'fake.io']
        self.test_users = ['alice', 'bob', 'charlie', 'diana', 'eve']
        self.spam_indicators = [
            'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X',
            'URGENT BUSINESS PROPOSAL',
            'YOU HAVE WON $1,000,000',
            'CLICK HERE TO CLAIM YOUR PRIZE'
        ]
        self.virus_signatures = [
            'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        ]
        
        self.results = []
    
    def log(self, message: str, level: str = "INFO"):
        """Enhanced logging with timestamps"""
        timestamp = time.strftime("%H:%M:%S")
        colors = {
            "INFO": "\033[36m",     # Cyan
            "SUCCESS": "\033[32m",  # Green
            "WARNING": "\033[33m",  # Yellow
            "ERROR": "\033[31m",    # Red
            "RESET": "\033[0m"      # Reset
        }
        color = colors.get(level, colors["INFO"])
        print(f"{color}[{timestamp}] {level}: {message}{colors['RESET']}")
    
    def check_services(self) -> bool:
        """Check if required services are running"""
        self.log("Checking service availability...")
        
        services = {
            'SMTP Server': (self.smtp_host, self.smtp_port),
            'Metrics Server': ('localhost', 8080),
            'Prometheus': ('localhost', 9090),
            'Grafana': ('localhost', 3000)
        }
        
        all_running = True
        for service, (host, port) in services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    self.log(f"✅ {service} is running on {host}:{port}", "SUCCESS")
                else:
                    self.log(f"❌ {service} is not accessible on {host}:{port}", "ERROR")
                    all_running = False
            except Exception as e:
                self.log(f"❌ {service} check failed: {e}", "ERROR")
                all_running = False
        
        return all_running
    
    def generate_smtp_basic_traffic(self, count: int = 20):
        """Generate basic SMTP traffic for Overview dashboard"""
        self.log(f"📧 Generating {count} basic SMTP messages for Overview dashboard...")
        
        successful = 0
        failed = 0
        
        for i in range(count):
            try:
                from_addr = f"{random.choice(self.test_users)}@{random.choice(self.test_domains)}"
                to_addr = f"{random.choice(self.test_users)}@{random.choice(self.test_domains)}"
                
                msg = MIMEText(f"Test message {i+1} for dashboard population at {time.ctime()}")
                msg['Subject'] = f"Dashboard Test Message {i+1}"
                msg['From'] = from_addr
                msg['To'] = to_addr
                
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.send_message(msg)
                server.quit()
                
                successful += 1
                if i % 5 == 0:
                    self.log(f"Sent {i+1}/{count} messages...")
                
                time.sleep(0.2)  # Brief delay
                
            except Exception as e:
                failed += 1
                if failed <= 3:  # Only log first few errors
                    self.log(f"Failed to send message {i+1}: {e}", "WARNING")
        
        self.log(f"✅ Basic SMTP traffic: {successful} sent, {failed} failed", "SUCCESS")
        return successful, failed
    
    def generate_authenticated_traffic(self, count: int = 15):
        """Generate authenticated SMTP traffic"""
        self.log(f"🔐 Generating {count} authenticated SMTP messages...")
        
        # Valid credentials (from demo setup)
        valid_credentials = [
            ('demo@example.com', 'demo123'),
            ('john.smith@example.com', 'password123'),
            ('user@example.com', 'userpass')
        ]
        
        successful = 0
        auth_failures = 0
        
        for i in range(count):
            try:
                # Mix of valid and invalid auth attempts
                if i % 4 == 0:  # 25% invalid auth
                    username = f"fake{i}@example.com"
                    password = "wrongpassword"
                else:
                    username, password = random.choice(valid_credentials)
                
                from_addr = username
                to_addr = f"{random.choice(self.test_users)}@{random.choice(self.test_domains)}"
                
                msg = MIMEText(f"Authenticated message {i+1} from {username}")
                msg['Subject'] = f"Auth Test Message {i+1}"
                msg['From'] = from_addr
                msg['To'] = to_addr
                
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.starttls()
                
                try:
                    server.login(username, password)
                    server.send_message(msg)
                    successful += 1
                except smtplib.SMTPAuthenticationError:
                    auth_failures += 1
                    if auth_failures <= 3:
                        self.log(f"Expected auth failure for {username}", "WARNING")
                
                server.quit()
                time.sleep(0.3)
                
            except Exception as e:
                if "authentication" not in str(e).lower():
                    self.log(f"Unexpected error in auth test {i+1}: {e}", "ERROR")
        
        self.log(f"✅ Auth traffic: {successful} successful, {auth_failures} auth failures", "SUCCESS")
        return successful, auth_failures
    
    def generate_greylisting_traffic(self, count: int = 10):
        """Generate traffic to trigger greylisting"""
        self.log(f"⏳ Generating {count} messages to trigger greylisting...")
        
        # Simulate new senders to trigger greylisting
        new_senders = [f"newsender{i}@{random.choice(self.test_domains)}" for i in range(count)]
        
        greylisted = 0
        accepted = 0
        
        for i, sender in enumerate(new_senders):
            try:
                to_addr = f"{random.choice(self.test_users)}@example.com"
                
                msg = MIMEText(f"New sender message {i+1} - should trigger greylisting")
                msg['Subject'] = f"Greylisting Test {i+1}"
                msg['From'] = sender
                msg['To'] = to_addr
                
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                response = server.send_message(msg)
                server.quit()
                
                # Check response for greylisting indicators
                if "greylist" in str(response).lower() or "try again" in str(response).lower():
                    greylisted += 1
                else:
                    accepted += 1
                
                time.sleep(0.5)
                
            except Exception as e:
                if "greylist" in str(e).lower():
                    greylisted += 1
                else:
                    self.log(f"Greylisting test {i+1} error: {e}", "WARNING")
        
        self.log(f"✅ Greylisting: {greylisted} greylisted, {accepted} accepted", "SUCCESS")
        return greylisted, accepted
    
    def generate_security_events(self, count: int = 8):
        """Generate security events for Security dashboard"""
        self.log(f"🛡️ Generating {count} security events...")
        
        virus_detected = 0
        spam_detected = 0
        security_blocks = 0
        
        for i in range(count):
            try:
                if i % 3 == 0:  # Virus test
                    from_addr = f"virus{i}@malicious.com"
                    to_addr = f"{random.choice(self.test_users)}@example.com"
                    content = f"Virus test message {i+1}\n\n{random.choice(self.virus_signatures)}"
                    subject = f"VIRUS TEST {i+1}"
                    
                elif i % 3 == 1:  # Spam test
                    from_addr = f"spam{i}@suspicious.net"
                    to_addr = f"{random.choice(self.test_users)}@example.com"
                    content = f"Spam test message {i+1}\n\n{random.choice(self.spam_indicators)}"
                    subject = f"SPAM TEST - {random.choice(['URGENT', 'FREE MONEY', 'WINNER'])}"
                    
                else:  # Suspicious activity
                    from_addr = f"suspicious{i}@blocked.org"
                    to_addr = f"{random.choice(self.test_users)}@example.com"
                    content = f"Suspicious activity test {i+1}"
                    subject = f"SECURITY TEST {i+1}"
                
                msg = MIMEText(content)
                msg['Subject'] = subject
                msg['From'] = from_addr
                msg['To'] = to_addr
                
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                
                try:
                    server.send_message(msg)
                    # If sent successfully, it might still be caught by filters
                    self.log(f"Security test message {i+1} sent (may be filtered)", "WARNING")
                except Exception as e:
                    if "virus" in str(e).lower():
                        virus_detected += 1
                    elif "spam" in str(e).lower():
                        spam_detected += 1
                    else:
                        security_blocks += 1
                
                server.quit()
                time.sleep(0.4)
                
            except Exception as e:
                self.log(f"Security test {i+1} error: {e}", "WARNING")
        
        self.log(f"✅ Security events: {virus_detected} virus, {spam_detected} spam, {security_blocks} blocked", "SUCCESS")
        return virus_detected, spam_detected, security_blocks
    
    def generate_queue_load(self, count: int = 25):
        """Generate load to populate queue metrics"""
        self.log(f"📦 Generating {count} messages for queue population...")
        
        def send_batch(batch_size: int, delay: float):
            """Send a batch of messages with specified delay"""
            for i in range(batch_size):
                try:
                    from_addr = f"queue{i}@{random.choice(self.test_domains)}"
                    to_addr = f"delivery{i}@{random.choice(self.test_domains)}"
                    
                    # Vary message sizes
                    content_size = random.choice([100, 500, 1000, 2000])
                    content = "X" * content_size + f"\n\nQueue test message {i+1}"
                    
                    msg = MIMEText(content)
                    msg['Subject'] = f"Queue Load Test {i+1}"
                    msg['From'] = from_addr
                    msg['To'] = to_addr
                    
                    server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                    server.send_message(msg)
                    server.quit()
                    
                    time.sleep(delay)
                    
                except Exception as e:
                    self.log(f"Queue message {i+1} failed: {e}", "WARNING")
        
        # Send messages in batches to create queue buildup
        self.log("Sending fast batch (queue buildup)...")
        send_batch(count // 2, 0.1)
        
        time.sleep(2)
        
        self.log("Sending slower batch (queue processing)...")
        send_batch(count // 2, 0.5)
        
        self.log(f"✅ Queue load generation completed", "SUCCESS")
    
    def concurrent_load_test(self, threads: int = 5, messages_per_thread: int = 10):
        """Generate concurrent load for performance metrics"""
        self.log(f"⚡ Running concurrent load test: {threads} threads, {messages_per_thread} messages each...")
        
        def worker(thread_id: int):
            """Worker function for concurrent testing"""
            successes = 0
            failures = 0
            
            for i in range(messages_per_thread):
                try:
                    from_addr = f"thread{thread_id}_msg{i}@perf.test"
                    to_addr = f"target{i}@example.com"
                    
                    msg = MIMEText(f"Concurrent test message from thread {thread_id}, message {i+1}")
                    msg['Subject'] = f"Perf Test T{thread_id}M{i+1}"
                    msg['From'] = from_addr
                    msg['To'] = to_addr
                    
                    server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                    server.send_message(msg)
                    server.quit()
                    
                    successes += 1
                    time.sleep(0.05)  # Very brief delay
                    
                except Exception as e:
                    failures += 1
            
            return successes, failures
        
        # Execute concurrent workers
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(worker, i) for i in range(threads)]
            
            total_successes = 0
            total_failures = 0
            
            for future in futures:
                try:
                    successes, failures = future.result()
                    total_successes += successes
                    total_failures += failures
                except Exception as e:
                    self.log(f"Thread execution error: {e}", "ERROR")
        
        self.log(f"✅ Concurrent load: {total_successes} successful, {total_failures} failed", "SUCCESS")
        return total_successes, total_failures
    
    def check_metrics_endpoint(self):
        """Verify metrics are being generated"""
        self.log("📊 Checking metrics endpoint...")
        
        try:
            response = requests.get(self.metrics_url, timeout=5)
            if response.status_code == 200:
                metrics_text = response.text
                
                # Count different metric types
                smtp_metrics = len([line for line in metrics_text.split('\n') 
                                  if 'elemta_smtp' in line and not line.startswith('#')])
                queue_metrics = len([line for line in metrics_text.split('\n') 
                                   if 'elemta_queue' in line and not line.startswith('#')])
                security_metrics = len([line for line in metrics_text.split('\n') 
                                      if 'elemta_security' in line and not line.startswith('#')])
                
                self.log(f"✅ Metrics available: {smtp_metrics} SMTP, {queue_metrics} queue, {security_metrics} security", "SUCCESS")
                return True
            else:
                self.log(f"❌ Metrics endpoint returned {response.status_code}", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"❌ Failed to check metrics: {e}", "ERROR")
            return False
    
    def run_full_dashboard_population(self):
        """Run complete dashboard population test"""
        self.log("🚀 Starting comprehensive dashboard population test...", "SUCCESS")
        self.log("=" * 60)
        
        # Check prerequisites
        if not self.check_services():
            self.log("❌ Required services not available. Aborting.", "ERROR")
            return False
        
        start_time = time.time()
        
        try:
            # Test 1: Basic SMTP traffic (Overview Dashboard)
            self.log("\n📊 PHASE 1: Basic SMTP Traffic (Overview Dashboard)")
            self.generate_smtp_basic_traffic(20)
            time.sleep(2)
            
            # Test 2: Authentication traffic (Security Dashboard)
            self.log("\n🔐 PHASE 2: Authentication Tests (Security Dashboard)")
            self.generate_authenticated_traffic(15)
            time.sleep(2)
            
            # Test 3: Greylisting traffic (Greylisting Dashboard)
            self.log("\n⏳ PHASE 3: Greylisting Tests (Greylisting Dashboard)")
            self.generate_greylisting_traffic(10)
            time.sleep(2)
            
            # Test 4: Security events (Security Dashboard)
            self.log("\n🛡️ PHASE 4: Security Events (Security Dashboard)")
            self.generate_security_events(8)
            time.sleep(2)
            
            # Test 5: Queue load (Main Dashboard)
            self.log("\n📦 PHASE 5: Queue Load Tests (Main Dashboard)")
            self.generate_queue_load(25)
            time.sleep(2)
            
            # Test 6: Performance load (Main Dashboard)
            self.log("\n⚡ PHASE 6: Performance Tests (Main Dashboard)")
            self.concurrent_load_test(5, 10)
            time.sleep(2)
            
            # Verify metrics
            self.log("\n📊 PHASE 7: Metrics Verification")
            metrics_ok = self.check_metrics_endpoint()
            
            total_time = time.time() - start_time
            
            self.log("\n" + "=" * 60)
            self.log(f"🎉 Dashboard population test completed in {total_time:.1f} seconds!", "SUCCESS")
            
            if metrics_ok:
                self.log("✅ All dashboards should now show data!", "SUCCESS")
                self.log("🌐 Check your dashboards at:", "SUCCESS")
                self.log("   • Grafana: http://localhost:3000 (admin:elemta123)")
                self.log("   • Prometheus: http://localhost:9090")
                self.log("   • Metrics: http://localhost:8080/metrics")
            else:
                self.log("⚠️ Metrics verification failed - check service status", "WARNING")
            
            return True
            
        except Exception as e:
            self.log(f"❌ Dashboard population test failed: {e}", "ERROR")
            return False

def main():
    """Main execution function"""
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("""
Dashboard Population Test Script

This script generates comprehensive test traffic to populate all Elemta Grafana dashboards:
• Overview Dashboard - Basic SMTP metrics
• Main Dashboard - Detailed performance and queue metrics  
• Greylisting Dashboard - Greylisting events and statistics
• Security Dashboard - Authentication, virus, spam events
• Let's Encrypt Dashboard - Certificate metrics (already working)

Usage:
  python3 scripts/test-dashboard-population.py

Prerequisites:
  • Docker services running (docker-compose up -d)
  • All 12 services healthy
  • Grafana accessible at localhost:3000
  • Prometheus accessible at localhost:9090
  • Metrics server accessible at localhost:8080

The script will generate:
  • ~80 SMTP messages of various types
  • Authentication success/failure events
  • Greylisting triggers
  • Security events (virus/spam detection)
  • Queue load scenarios
  • Concurrent performance tests
        """)
        return
    
    populator = DashboardPopulator()
    success = populator.run_full_dashboard_population()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
