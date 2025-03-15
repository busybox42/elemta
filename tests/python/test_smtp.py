#!/usr/bin/env python3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# SMTP server details
smtp_server = "localhost"
smtp_port = 2525

# Email details
sender_email = "sender@example.com"
receiver_email = "recipient@example.com"
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
    
    # Start TLS if needed (not needed for our test)
    # server.starttls()
    
    # Authentication if needed (not needed for our test)
    # server.login("username", "password")
    
    # Send email
    print("Sending email...")
    server.sendmail(sender_email, receiver_email, message.as_string())
    print("Email sent successfully!")
    
    # Close connection
    server.quit()
    
except Exception as e:
    print(f"Error: {e}") 