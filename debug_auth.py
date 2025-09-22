#!/usr/bin/env python3
"""
Debug authentication test
"""

import socket
import base64

def test_auth_plain():
    """Test AUTH PLAIN with detailed debugging"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('localhost', 2525))
        
        # Read greeting
        greeting = sock.recv(1024).decode()
        print(f"Greeting: {greeting.strip()}")
        
        # Send EHLO
        sock.send(b'EHLO test.com\r\n')
        ehlo_response = sock.recv(1024).decode()
        print(f"EHLO response: {ehlo_response.strip()}")
        
        # Test AUTH PLAIN
        sock.send(b'AUTH PLAIN\r\n')
        auth_response = sock.recv(1024).decode()
        print(f"AUTH PLAIN response: {repr(auth_response)}")
        print(f"Starts with 334: {auth_response.startswith('334')}")
        
        if not auth_response.startswith("334"):
            print("AUTH PLAIN failed - not 334 response")
            sock.close()
            return False
        
        # Send credentials
        credentials = base64.b64encode(b'\x00demo@example.com\x00demo123').decode()
        print(f"Sending credentials: {credentials}")
        sock.send(f'{credentials}\r\n'.encode())
        
        cred_response = sock.recv(1024).decode()
        print(f"Credentials response: {repr(cred_response)}")
        print(f"Starts with 235: {cred_response.startswith('235')}")
        
        sock.close()
        
        if cred_response.startswith("235"):
            print("Authentication successful!")
            return True
        else:
            print("Authentication failed!")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    test_auth_plain()
