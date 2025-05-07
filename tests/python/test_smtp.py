#!/usr/bin/env python3
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sys
import argparse

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Test Elemta SMTP server with and without STARTTLS')
    parser.add_argument('--host', default='localhost', help='SMTP server hostname')
    parser.add_argument('--port', type=int, default=2525, help='SMTP server port')
    parser.add_argument('--use-starttls', action='store_true', help='Use STARTTLS to secure the connection')
    parser.add_argument('--from', dest='sender', default='sender@example.com', help='Sender email address')
    parser.add_argument('--to', dest='recipient', default='recipient@example.com', help='Recipient email address')
    
    args = parser.parse_args()

    # SMTP server details
    smtp_server = args.host
    smtp_port = args.port
    use_starttls = args.use_starttls

    # Email details
    sender_email = args.sender
    receiver_email = args.recipient
    subject = "Test Email from Elemta SMTP Server"
    message_text = "This is a test email sent through the Elemta SMTP server."

    # Create a multipart message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    # Add message body
    message.attach(MIMEText(message_text, "plain"))

    try:
        # Create SMTP session
        print(f"Connecting to {smtp_server}:{smtp_port}...")
        server = smtplib.SMTP(smtp_server, smtp_port)
        
        # Enable debug output
        server.set_debuglevel(1)
        
        # Start TLS if requested
        if use_starttls:
            print("Attempting STARTTLS upgrade...")
            context = ssl.create_default_context()
            server.starttls(context=context)
            print("Connection upgraded to TLS")
        
        # Authentication if needed (not needed for our test)
        # server.login("username", "password")
        
        # Send email
        print("Sending email...")
        server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully!")
        
        # Close connection
        server.quit()
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 