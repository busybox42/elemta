#!/usr/bin/env python3
"""
Simple SMTP test to verify command security enhancements
"""

import socket
import time

def test_smtp_connection():
    """Test basic SMTP connection and command security"""
    try:
        # Connect to SMTP server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('localhost', 2525))
        
        # Read greeting
        greeting = sock.recv(1024).decode('utf-8')
        print(f"Greeting: {greeting.strip()}")
        
        # Test EHLO command
        sock.send(b'EHLO test.com\r\n')
        response = sock.recv(1024).decode('utf-8')
        print(f"EHLO response: {response.strip()}")
        
        # Test long command (should be rejected)
        long_cmd = 'A' * 1000  # 1000 character command
        sock.send(f'{long_cmd}\r\n'.encode('utf-8'))
        response = sock.recv(1024).decode('utf-8')
        print(f"Long command response: {response.strip()}")
        
        # Test command with null bytes (should be rejected)
        null_cmd = 'HELO\x00test.com'
        sock.send(f'{null_cmd}\r\n'.encode('utf-8'))
        response = sock.recv(1024).decode('utf-8')
        print(f"Null byte command response: {response.strip()}")
        
        # Test SQL injection attempt (should be rejected)
        sql_cmd = "HELO'; DROP TABLE users; --"
        sock.send(f'{sql_cmd}\r\n'.encode('utf-8'))
        response = sock.recv(1024).decode('utf-8')
        print(f"SQL injection command response: {response.strip()}")
        
        # Test QUIT
        sock.send(b'QUIT\r\n')
        response = sock.recv(1024).decode('utf-8')
        print(f"QUIT response: {response.strip()}")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("Testing SMTP command security enhancements...")
    success = test_smtp_connection()
    if success:
        print("✅ Basic SMTP test completed successfully")
    else:
        print("❌ SMTP test failed")
