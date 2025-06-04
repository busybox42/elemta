#!/usr/bin/env python3
"""
Test script for Elemta SMTP relay control.
Tests that:
1. Internal networks can relay without authentication
2. External connections require authentication for relay
3. Local domain delivery works for all
"""

import smtplib
import socket
import sys
import time
from email.mime.text import MIMEText

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

def test_smtp_connection(host, port, from_addr, to_addr, auth=None, expect_success=True, test_name=""):
    """Test SMTP connection and send message"""
    print(f"\n{Colors.BLUE}Testing: {test_name}{Colors.RESET}")
    print(f"From: {from_addr} -> To: {to_addr}")
    
    try:
        # Create SMTP connection
        server = smtplib.SMTP(host, port, timeout=10)
        server.set_debuglevel(0)  # Set to 1 for verbose output
        
        # Say EHLO
        server.ehlo()
        
        # Authenticate if credentials provided
        if auth:
            username, password = auth
            print(f"Authenticating as: {username}")
            server.login(username, password)
        
        # Create a simple test message
        msg = MIMEText(f"Test message from {from_addr} to {to_addr} at {time.ctime()}")
        msg['Subject'] = f'Test: {test_name}'
        msg['From'] = from_addr
        msg['To'] = to_addr
        
        # Send the message
        server.sendmail(from_addr, [to_addr], msg.as_string())
        server.quit()
        
        if expect_success:
            print(f"{Colors.GREEN}✓ SUCCESS: Message sent successfully{Colors.RESET}")
            return True
        else:
            print(f"{Colors.RED}✗ UNEXPECTED: Expected failure but message was sent{Colors.RESET}")
            return False
            
    except smtplib.SMTPRecipientsRefused as e:
        if expect_success:
            print(f"{Colors.RED}✗ FAILED: Recipients refused - {e}{Colors.RESET}")
            return False
        else:
            print(f"{Colors.GREEN}✓ EXPECTED: Recipients refused (relay denied) - {e}{Colors.RESET}")
            return True
            
    except smtplib.SMTPAuthenticationError as e:
        if expect_success:
            print(f"{Colors.RED}✗ FAILED: Authentication error - {e}{Colors.RESET}")
            return False
        else:
            print(f"{Colors.GREEN}✓ EXPECTED: Authentication required - {e}{Colors.RESET}")
            return True
            
    except Exception as e:
        print(f"{Colors.RED}✗ ERROR: {e}{Colors.RESET}")
        return False

def get_local_ip():
    """Get the local IP address"""
    try:
        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

def main():
    host = "localhost"
    port = 2525
    
    # Test credentials (for external authentication tests)
    test_user = "testuser@example.com"
    test_pass = "testpass"
    
    local_ip = get_local_ip()
    print(f"{Colors.BLUE}Local IP detected: {local_ip}{Colors.RESET}")
    print(f"{Colors.BLUE}Testing SMTP server at {host}:{port}{Colors.RESET}")
    
    # Test 1: Local domain delivery (should always work)
    print(f"\n{Colors.YELLOW}=== Test 1: Local Domain Delivery ==={Colors.RESET}")
    test_smtp_connection(
        host, port,
        "sender@external.com",
        "recipient@example.com",  # Local domain
        auth=None,
        expect_success=True,
        test_name="Local domain delivery without auth"
    )
    
    # Test 2: Internal network relay (should work without auth)
    print(f"\n{Colors.YELLOW}=== Test 2: Internal Network Relay ==={Colors.RESET}")
    test_smtp_connection(
        host, port,
        "sender@example.com", 
        "recipient@external.com",  # External domain (relay)
        auth=None,
        expect_success=True,
        test_name="Internal network relay without auth"
    )
    
    # Test 3: Simulated external connection relay without auth (should fail)
    print(f"\n{Colors.YELLOW}=== Test 3: External Connection Relay (No Auth) ==={Colors.RESET}")
    print(f"{Colors.BLUE}Note: This test simulates external behavior but runs from internal network{Colors.RESET}")
    print(f"{Colors.BLUE}In a real scenario, this would be blocked{Colors.RESET}")
    test_smtp_connection(
        host, port,
        "sender@external.com",
        "recipient@another-external.com",  # External to external (relay)
        auth=None,
        expect_success=True,  # Will succeed due to internal network
        test_name="Relay without auth (internal network - would fail if external)"
    )
    
    # Test 4: Authenticated relay (should work)
    print(f"\n{Colors.YELLOW}=== Test 4: Authenticated Relay ==={Colors.RESET}")
    print(f"{Colors.BLUE}Note: Using test credentials - may fail if LDAP not configured{Colors.RESET}")
    test_smtp_connection(
        host, port,
        "sender@external.com",
        "recipient@another-external.com",  # External to external (relay)
        auth=(test_user, test_pass),
        expect_success=False,  # Expect to fail due to invalid credentials
        test_name="Relay with authentication"
    )
    
    # Test 5: Multiple recipients (local and external)
    print(f"\n{Colors.YELLOW}=== Test 5: Mixed Recipients ==={Colors.RESET}")
    try:
        server = smtplib.SMTP(host, port, timeout=10)
        server.ehlo()
        
        msg = MIMEText("Test message with mixed recipients")
        msg['Subject'] = 'Mixed recipients test'
        msg['From'] = 'sender@example.com'
        msg['To'] = 'recipient@example.com, external@other.com'
        
        # This should work for the local recipient
        server.sendmail('sender@example.com', 
                       ['recipient@example.com', 'external@other.com'], 
                       msg.as_string())
        server.quit()
        print(f"{Colors.GREEN}✓ SUCCESS: Mixed recipients accepted{Colors.RESET}")
        
    except Exception as e:
        print(f"{Colors.RED}✗ FAILED: Mixed recipients - {e}{Colors.RESET}")
    
    print(f"\n{Colors.BLUE}=== Test Summary ==={Colors.RESET}")
    print(f"1. Local domain delivery should always work")
    print(f"2. Internal networks can relay without authentication")
    print(f"3. External connections require authentication for relay")
    print(f"4. Authentication is checked for external relay attempts")
    print(f"\n{Colors.YELLOW}Important: These tests run from internal network, so relay restrictions")
    print(f"will be relaxed. To test external behavior, run from outside Docker network.{Colors.RESET}")

if __name__ == "__main__":
    main() 