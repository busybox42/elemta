#!/usr/bin/env python3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# SMTP server details
smtp_server = "localhost"
smtp_port = 2526

# Authentication details
username = "testuser"
password = "testpass"

# Email details
sender_email = "sender@example.com"
receiver_email = "recipient@example.com"
subject = "Test Email with Authentication"
message_text = "This is a test email sent through the Elemta SMTP server with authentication."

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
    
    # Print server capabilities
    print("Server capabilities:")
    server.ehlo()
    
    # Try authentication
    print(f"Attempting to authenticate as {username}...")
    try:
        server.login(username, password)
        print("Authentication successful!")
    except smtplib.SMTPException as e:
        print(f"Authentication failed: {e}")
    
    # Send email
    print("Sending email...")
    server.sendmail(sender_email, receiver_email, message.as_string())
    print("Email sent successfully!")
    
    # Close connection
    server.quit()
    
except Exception as e:
    print(f"Error: {e}") 