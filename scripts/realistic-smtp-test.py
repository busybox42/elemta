#!/usr/bin/env python3
"""
Realistic SMTP Test Script - Generates Real Traffic for Dashboard Testing
"""

import smtplib
import time
import random
import threading
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import argparse

class RealisticSMTPTester:
    def __init__(self, smtp_host='localhost', smtp_port=2525):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.stats = {'sent': 0, 'failed': 0, 'auth_success': 0, 'auth_failed': 0}
        
        # Realistic test data
        self.domains = ['example.com', 'test.org', 'company.net']
        self.users = ['alice', 'bob', 'charlie', 'diana', 'eve', 'frank']
        self.existing_users = ['demo@example.com', 'john.smith@example.com']
        
        self.normal_subjects = [
            'Meeting Reminder', 'Weekly Report', 'Project Update', 'Team Lunch',
            'Budget Review', 'Client Presentation', 'Documentation Update'
        ]
        
        self.suspicious_subjects = [
            'URGENT: Wire Transfer Required', 'You Won $1,000,000',
            'Claim Your Prize Now', 'Account Suspended - Act Now'
        ]
    
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {"INFO": "\033[36m", "SUCCESS": "\033[32m", "WARNING": "\033[33m", "ERROR": "\033[31m", "RESET": "\033[0m"}
        color = colors.get(level, colors["INFO"])
        print(f"{color}[{timestamp}] {message}{colors['RESET']}")
    
    def send_normal_email(self, from_addr=None, to_addr=None, use_auth=False):
        if not from_addr:
            from_addr = f"{random.choice(self.users)}@{random.choice(self.domains)}"
        if not to_addr:
            to_addr = random.choice(self.existing_users)  # Use existing users for delivery
        
        subject = random.choice(self.normal_subjects)
        content = f"""Hi there,

Hope this email finds you well. I wanted to follow up on our previous conversation.

The meeting is scheduled for next Tuesday at 2 PM. Please review the attached document and let me know your thoughts.

Best regards,
{from_addr.split('@')[0].title()}"""
        
        try:
            msg = MIMEText(content)
            msg['Subject'] = subject
            msg['From'] = from_addr
            msg['To'] = to_addr
            msg['X-Test-Type'] = 'normal'
            
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            
            if use_auth:
                try:
                    server.starttls()
                    server.login('demo@example.com', 'demo123')
                    self.stats['auth_success'] += 1
                except:
                    self.stats['auth_failed'] += 1
                    raise
            
            server.send_message(msg)
            server.quit()
            self.stats['sent'] += 1
            return True
            
        except Exception as e:
            self.stats['failed'] += 1
            self.log(f"Failed to send normal email: {e}", "WARNING")
            return False
    
    def send_suspicious_email(self, from_addr=None, to_addr=None):
        if not from_addr:
            from_addr = f"noreply@{random.choice(['suspicious.com', 'phishing.net'])}"
        if not to_addr:
            to_addr = random.choice(self.existing_users)
        
        subject = random.choice(self.suspicious_subjects)
        content = f"""URGENT ACTION REQUIRED

Your account will be suspended unless you act immediately.

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

Click here: http://suspicious-link.fake

Reply with your SSN and bank details."""
        
        try:
            msg = MIMEText(content)
            msg['Subject'] = subject
            msg['From'] = from_addr
            msg['To'] = to_addr
            msg['X-Test-Type'] = 'suspicious'
            
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.send_message(msg)
            server.quit()
            self.stats['sent'] += 1
            return True
            
        except Exception as e:
            self.stats['failed'] += 1
            if 'spam' in str(e).lower() or 'block' in str(e).lower():
                self.log(f"Suspicious email blocked (expected): {e}", "SUCCESS")
            else:
                self.log(f"Failed to send suspicious email: {e}", "WARNING")
            return False
    
    def send_large_email(self, from_addr=None, to_addr=None):
        if not from_addr:
            from_addr = f"{random.choice(self.users)}@{random.choice(self.domains)}"
        if not to_addr:
            to_addr = random.choice(self.existing_users)
        
        subject = f"Large Document - {random.randint(1000, 9999)}"
        large_content = "This is a large email for testing purposes.\n" * 500
        large_content += f"\nGenerated at: {datetime.now()}\n"
        
        try:
            msg = MIMEText(large_content)
            msg['Subject'] = subject
            msg['From'] = from_addr
            msg['To'] = to_addr
            msg['X-Test-Type'] = 'large'
            
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.send_message(msg)
            server.quit()
            self.stats['sent'] += 1
            return True
            
        except Exception as e:
            self.stats['failed'] += 1
            self.log(f"Failed to send large email: {e}", "WARNING")
            return False
    
    def send_burst_emails(self, count=10, delay=0.1):
        self.log(f"Sending burst of {count} emails (delay: {delay}s)")
        
        def send_single():
            return self.send_normal_email()
        
        threads = []
        for i in range(count):
            thread = threading.Thread(target=send_single)
            threads.append(thread)
            thread.start()
            time.sleep(delay)
        
        for thread in threads:
            thread.join()
    
    def run_realistic_test_suite(self, duration_minutes=5):
        self.log("🚀 Starting Realistic SMTP Test Suite", "SUCCESS")
        self.log(f"Duration: {duration_minutes} minutes")
        self.log(f"Target: {self.smtp_host}:{self.smtp_port}")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        test_cycle = 0
        
        while time.time() < end_time:
            test_cycle += 1
            self.log(f"Test Cycle {test_cycle}")
            
            # Normal emails (70% of traffic)
            for _ in range(7):
                self.send_normal_email()
                time.sleep(random.uniform(1, 3))
            
            # Suspicious emails (15% of traffic)
            for _ in range(2):
                self.send_suspicious_email()
                time.sleep(random.uniform(0.5, 2))
            
            # Large emails (10% of traffic)
            if random.random() < 0.5:
                self.send_large_email()
                time.sleep(random.uniform(1, 2))
            
            # Authentication test (5% of traffic)
            if random.random() < 0.3:
                self.send_normal_email(use_auth=True)
                time.sleep(random.uniform(1, 3))
            
            # Burst test every 3 cycles
            if test_cycle % 3 == 0:
                self.send_burst_emails(count=5, delay=0.2)
                time.sleep(5)
            
            time.sleep(random.uniform(2, 5))
        
        self.print_final_stats()
    
    def print_final_stats(self):
        total_attempts = self.stats['sent'] + self.stats['failed']
        success_rate = (self.stats['sent'] / total_attempts * 100) if total_attempts > 0 else 0
        
        self.log("\n" + "="*50, "SUCCESS")
        self.log("📊 REALISTIC SMTP TEST RESULTS", "SUCCESS")
        self.log("="*50, "SUCCESS")
        self.log(f"📧 Total Emails Sent: {self.stats['sent']}")
        self.log(f"❌ Failed Attempts: {self.stats['failed']}")
        self.log(f"📈 Success Rate: {success_rate:.1f}%")
        self.log(f"🔐 Auth Successful: {self.stats['auth_success']}")
        self.log(f"🚫 Auth Failed: {self.stats['auth_failed']}")
        self.log("="*50, "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description='Realistic SMTP Traffic Generator')
    parser.add_argument('--host', default='localhost', help='SMTP server host')
    parser.add_argument('--port', type=int, default=2525, help='SMTP server port')
    parser.add_argument('--duration', type=int, default=5, help='Test duration in minutes')
    parser.add_argument('--test-type', choices=['normal', 'suspicious', 'large', 'burst', 'full'], 
                       default='full', help='Type of test to run')
    parser.add_argument('--count', type=int, default=10, help='Number of emails for single test types')
    
    args = parser.parse_args()
    tester = RealisticSMTPTester(args.host, args.port)
    
    if args.test_type == 'full':
        tester.run_realistic_test_suite(args.duration)
    elif args.test_type == 'burst':
        tester.send_burst_emails(args.count, 0.1)
    else:
        for i in range(args.count):
            if args.test_type == 'normal':
                tester.send_normal_email()
            elif args.test_type == 'suspicious':
                tester.send_suspicious_email()
            elif args.test_type == 'large':
                tester.send_large_email()
            time.sleep(1)
    
    tester.print_final_stats()

if __name__ == "__main__":
    main()
