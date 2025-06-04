#!/usr/bin/env python3

import smtplib
from email.mime.text import MIMEText
import time

def test_smtp_delivery():
    try:
        print("Testing SMTP delivery through Docker container...")
        
        # Connect to Docker SMTP server
        smtp = smtplib.SMTP('localhost', 2525)
        smtp.set_debuglevel(1)
        
        # Create test message
        msg = MIMEText('Test message for LMTP delivery to Dovecot!\n\nThis message should be delivered via LMTP to the Dovecot container.')
        msg['Subject'] = 'Test LMTP Delivery via Docker'
        msg['From'] = 'sender@example.com'
        msg['To'] = 'recipient@example.com'
        
        print("\nSending email...")
        smtp.sendmail('sender@example.com', ['recipient@example.com'], msg.as_string())
        smtp.quit()
        
        print("✅ Email sent successfully!")
        print("Check Docker logs and Dovecot mailbox for delivery.")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_smtp_delivery() 