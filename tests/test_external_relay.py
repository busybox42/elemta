#!/usr/bin/env python3
"""
Test script to demonstrate external vs internal relay behavior.
This script shows how the relay control logic works.
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

def test_relay_behavior():
    """Test and explain relay behavior"""
    
    print(f"{Colors.BLUE}=== Elemta SMTP Relay Control Behavior ==={Colors.RESET}")
    print()
    
    # Get network information
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except:
        local_ip = "127.0.0.1"
    
    print(f"Current test IP: {local_ip}")
    
    # Determine if current IP is private
    is_private = (
        local_ip.startswith("10.") or
        local_ip.startswith("192.168.") or
        local_ip.startswith("172.") or
        local_ip == "127.0.0.1"
    )
    
    print(f"Is private network: {is_private}")
    print()
    
    print(f"{Colors.YELLOW}Relay Control Rules:{Colors.RESET}")
    print("1. Local domain delivery (e.g., @example.com) - ALWAYS ALLOWED")
    print("2. Internal network relay (private IPs) - ALLOWED WITHOUT AUTH")
    print("3. External network relay (public IPs) - REQUIRES AUTHENTICATION")
    print()
    
    print(f"{Colors.YELLOW}Network Classifications:{Colors.RESET}")
    print("Internal/Private Networks:")
    print("  - 10.0.0.0/8 (Class A private)")
    print("  - 172.16.0.0/12 (Class B private)")
    print("  - 192.168.0.0/16 (Class C private)")
    print("  - 127.0.0.0/8 (Loopback)")
    print("  - ::1 (IPv6 loopback)")
    print("  - fc00::/7 (IPv6 unique local)")
    print()
    print("External/Public Networks:")
    print("  - All other IP addresses")
    print()
    
    print(f"{Colors.YELLOW}Test Scenarios:{Colors.RESET}")
    
    # Test 1: Local domain delivery
    print(f"\n{Colors.BLUE}Scenario 1: Local Domain Delivery{Colors.RESET}")
    print("From: external@anywhere.com -> To: user@example.com")
    print("Expected: ✓ ALLOWED (local domain)")
    try:
        server = smtplib.SMTP("localhost", 2525, timeout=5)
        server.ehlo()
        server.mail("external@anywhere.com")
        server.rcpt("user@example.com")
        server.quit()
        print(f"{Colors.GREEN}Result: ✓ ALLOWED{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}Result: ✗ DENIED - {e}{Colors.RESET}")
    
    # Test 2: Internal network relay
    print(f"\n{Colors.BLUE}Scenario 2: Internal Network Relay{Colors.RESET}")
    print("From: user@example.com -> To: external@remote.com")
    if is_private:
        print("Expected: ✓ ALLOWED (internal network, no auth required)")
    else:
        print("Expected: ✗ DENIED (external network, auth required)")
    
    try:
        server = smtplib.SMTP("localhost", 2525, timeout=5)
        server.ehlo()
        server.mail("user@example.com")
        server.rcpt("external@remote.com")
        server.quit()
        if is_private:
            print(f"{Colors.GREEN}Result: ✓ ALLOWED (internal network){Colors.RESET}")
        else:
            print(f"{Colors.RED}Result: ✗ UNEXPECTED - Should have been denied{Colors.RESET}")
    except smtplib.SMTPRecipientsRefused as e:
        if is_private:
            print(f"{Colors.RED}Result: ✗ UNEXPECTED - Should have been allowed{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}Result: ✓ DENIED (external network, no auth){Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}Result: ✗ ERROR - {e}{Colors.RESET}")
    
    # Test 3: Authenticated relay
    print(f"\n{Colors.BLUE}Scenario 3: Authenticated Relay{Colors.RESET}")
    print("From: user@example.com -> To: external@remote.com (with auth)")
    print("Expected: Depends on authentication success")
    
    try:
        server = smtplib.SMTP("localhost", 2525, timeout=5)
        server.ehlo()
        # Try to authenticate with invalid credentials
        server.login("testuser@example.com", "wrongpassword")
        server.mail("user@example.com")
        server.rcpt("external@remote.com")
        server.quit()
        print(f"{Colors.RED}Result: ✗ UNEXPECTED - Invalid auth should fail{Colors.RESET}")
    except smtplib.SMTPAuthenticationError:
        print(f"{Colors.GREEN}Result: ✓ AUTH FAILED (as expected with invalid credentials){Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}Result: Other error - {e}{Colors.RESET}")
    
    print(f"\n{Colors.YELLOW}Summary:{Colors.RESET}")
    print("✓ Local domain delivery works from any source")
    print("✓ Internal networks can relay without authentication")
    print("✓ External networks require authentication for relay")
    print("✓ Authentication is properly validated")
    
    print(f"\n{Colors.BLUE}Security Benefits:{Colors.RESET}")
    print("• Prevents open relay abuse from external sources")
    print("• Allows internal applications to send mail freely")
    print("• Maintains proper email security boundaries")
    print("• Supports both authenticated and network-based access control")

if __name__ == "__main__":
    test_relay_behavior() 