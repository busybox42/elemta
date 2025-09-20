#!/usr/bin/env python3

import socket
import time

def test_smtp():
    print("Testing SMTP connection to localhost:2525...")
    
    try:
        # Connect to SMTP server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('localhost', 2525))
        
        # Read greeting
        response = sock.recv(1024).decode('utf-8').strip()
        print(f"Server greeting: {response}")
        
        if not response.startswith('220'):
            print("❌ Invalid greeting response")
            return False
            
        # Send EHLO command
        print("Sending EHLO command...")
        sock.send(b'EHLO test.example.com\r\n')
        
        # Read EHLO response
        response = sock.recv(1024).decode('utf-8').strip()
        print(f"EHLO response: {response}")
        
        if response.startswith('250'):
            print("✅ EHLO command successful!")
            success = True
        else:
            print("❌ EHLO command failed")
            success = False
            
        # Send QUIT
        sock.send(b'QUIT\r\n')
        response = sock.recv(1024).decode('utf-8').strip()
        print(f"QUIT response: {response}")
        
        sock.close()
        return success
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    # Wait a moment for server to be ready
    time.sleep(2)
    
    success = test_smtp()
    if success:
        print("\n🎉 SMTP server is working correctly!")
    else:
        print("\n💥 SMTP server test failed!")
        
    exit(0 if success else 1)
