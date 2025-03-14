#!/usr/bin/env python3
import smtplib
import sys
import traceback
from email.mime.text import MIMEText

def test_smtp_connection():
    print("Testing SMTP connection to localhost:2525...")
    try:
        # Connect to the SMTP server
        print("Attempting to connect...")
        server = smtplib.SMTP('localhost', 2525, timeout=10)
        server.set_debuglevel(2)  # Show detailed communication with the server
        print("Connection successful!")
        
        # Try sending a test email
        try:
            print("Creating test email...")
            msg = MIMEText("This is a test email from the Python script.")
            msg['Subject'] = 'SMTP Test'
            msg['From'] = 'test@example.com'
            msg['To'] = 'recipient@example.com'
            
            print("Sending email...")
            server.sendmail('test@example.com', ['recipient@example.com'], msg.as_string())
            print("Test email sent successfully!")
        except Exception as e:
            print(f"Error sending email: {e}")
            traceback.print_exc()
        
        # Close the connection
        print("Closing connection...")
        server.quit()
        return True
    except Exception as e:
        print(f"Connection failed: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Starting SMTP test...")
    success = test_smtp_connection()
    print(f"Test completed with {'success' if success else 'failure'}")
    sys.exit(0 if success else 1) 