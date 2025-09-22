#!/usr/bin/env python3
"""
Debug test to understand why security tests are failing
"""

import socket

def test_sql_injection():
    """Test SQL injection with detailed debugging"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('localhost', 2525))
        
        # Read greeting
        greeting = sock.recv(1024).decode()
        print(f"Greeting: {greeting.strip()}")
        
        # Send SQL injection command
        command = "HELO'; DROP TABLE users; --"
        print(f"Sending command: {repr(command)}")
        sock.send(f"{command}\r\n".encode())
        
        # Read response
        response = sock.recv(1024).decode()
        print(f"Response: {repr(response)}")
        print(f"Response stripped: {response.strip()}")
        
        # Check conditions
        print(f"Contains 'Invalid command name': {'Invalid command name' in response}")
        print(f"Contains '500': {'500' in response}")
        print(f"Starts with '500': {response.startswith('500')}")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    test_sql_injection()
