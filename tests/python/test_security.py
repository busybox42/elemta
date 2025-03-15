#!/usr/bin/env python3

import smtplib
import argparse
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# EICAR test string for antivirus testing
EICAR_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# GTUBE test string for antispam testing
GTUBE_STRING = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"

def test_antivirus(server, port, sender, recipient, debug=False):
    print(f"Testing antivirus scanning with EICAR test string...")
    print(f"Connecting to SMTP server at {server}:{port}...")
    
    try:
        # Create a message with the EICAR test string
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipient
        msg['Subject'] = "EICAR Test"
        
        # Add the EICAR test string to the message
        msg.attach(MIMEText(EICAR_STRING))
        
        # Connect to the SMTP server and send the message
        with smtplib.SMTP(server, port) as smtp:
            if debug:
                smtp.set_debuglevel(2)
            smtp.ehlo()
            print("Sending message with EICAR test string...")
            smtp.sendmail(sender, recipient, msg.as_string())
            
        print("Message sent - Antivirus scanning may not be working!")
        return False
    except smtplib.SMTPResponseException as e:
        if e.smtp_code >= 500:
            print(f"Message rejected with code {e.smtp_code}: {e.smtp_error}")
            print("Antivirus scanning is working correctly!")
            return True
        else:
            print(f"Unexpected SMTP response: {e.smtp_code} {e.smtp_error}")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_antispam(server, port, sender, recipient, debug=False):
    print(f"Testing antispam scanning with GTUBE test string...")
    print(f"Connecting to SMTP server at {server}:{port}...")
    
    try:
        # Create a message with the GTUBE test string
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipient
        msg['Subject'] = "GTUBE Test"
        
        # Add the GTUBE test string to the message
        msg.attach(MIMEText(GTUBE_STRING))
        
        # Connect to the SMTP server and send the message
        with smtplib.SMTP(server, port) as smtp:
            if debug:
                smtp.set_debuglevel(2)
            smtp.ehlo()
            print("Sending message with GTUBE test string...")
            smtp.sendmail(sender, recipient, msg.as_string())
            
        print("Message sent - Antispam scanning may not be working!")
        return False
    except smtplib.SMTPResponseException as e:
        if e.smtp_code >= 500:
            print(f"Message rejected with code {e.smtp_code}: {e.smtp_error}")
            print("Antispam scanning is working correctly!")
            return True
        else:
            print(f"Unexpected SMTP response: {e.smtp_code} {e.smtp_error}")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Test email security features")
    parser.add_argument("--server", default="localhost", help="SMTP server address")
    parser.add_argument("--port", type=int, default=2526, help="SMTP server port")
    parser.add_argument("--sender", default="sender@example.com", help="Sender email address")
    parser.add_argument("--recipient", default="recipient@example.com", help="Recipient email address")
    parser.add_argument("--test", choices=["virus", "spam", "all"], default="all", help="Test to run")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()
    
    print(f"Starting security tests against {args.server}:{args.port}")
    print(f"Debug mode: {'enabled' if args.debug else 'disabled'}")
    
    results = []
    
    if args.test == "virus" or args.test == "all":
        virus_result = test_antivirus(args.server, args.port, args.sender, args.recipient, args.debug)
        results.append(("Antivirus", virus_result))
    
    if args.test == "spam" or args.test == "all":
        spam_result = test_antispam(args.server, args.port, args.sender, args.recipient, args.debug)
        results.append(("Antispam", spam_result))
    
    print("\nTest Results:")
    for test_name, result in results:
        print(f"{test_name} Test: {'PASSED' if result else 'FAILED'}")
    
    if all(result for _, result in results):
        print("\nAll tests passed!")
        return 0
    else:
        print("\nSome tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 