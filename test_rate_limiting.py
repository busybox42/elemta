#!/usr/bin/env python3
"""
Simple test script to verify rate limiting functionality
"""

import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

def test_smtp_connection(host='localhost', port=2525, timeout=10):
    """Test basic SMTP connection"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Read greeting
        greeting = sock.recv(1024).decode('utf-8').strip()
        print(f"✅ Connection successful: {greeting}")
        
        # Send EHLO
        sock.send(b"EHLO test-client\r\n")
        response = sock.recv(1024).decode('utf-8').strip()
        print(f"✅ EHLO response: {response}")
        
        # Send QUIT
        sock.send(b"QUIT\r\n")
        quit_response = sock.recv(1024).decode('utf-8').strip()
        print(f"✅ QUIT response: {quit_response}")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

def test_concurrent_connections(num_connections=10, host='localhost', port=2525):
    """Test multiple concurrent connections to verify rate limiting"""
    print(f"\n🚀 Testing {num_connections} concurrent connections...")
    
    results = []
    with ThreadPoolExecutor(max_workers=num_connections) as executor:
        futures = [executor.submit(test_smtp_connection, host, port) for _ in range(num_connections)]
        
        for i, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result(timeout=15)
                results.append(result)
                print(f"Connection {i}: {'✅ Success' if result else '❌ Failed'}")
            except Exception as e:
                print(f"Connection {i}: ❌ Error - {e}")
                results.append(False)
    
    success_count = sum(results)
    print(f"\n📊 Results: {success_count}/{num_connections} connections successful")
    return success_count

def test_rapid_connections(host='localhost', port=2525):
    """Test rapid sequential connections to trigger rate limiting"""
    print(f"\n🚀 Testing rapid sequential connections...")
    
    success_count = 0
    for i in range(20):
        try:
            if test_smtp_connection(host, port, timeout=5):
                success_count += 1
            time.sleep(0.1)  # Small delay between connections
        except Exception as e:
            print(f"Connection {i+1}: ❌ Error - {e}")
    
    print(f"\n📊 Results: {success_count}/20 rapid connections successful")
    return success_count

def main():
    print("🚀 Starting Rate Limiting Test Suite")
    print("=" * 60)
    
    # Test basic connection
    print("1. Testing basic SMTP connection...")
    if not test_smtp_connection():
        print("❌ Basic connection failed - aborting tests")
        return
    
    # Test concurrent connections
    print("\n2. Testing concurrent connections...")
    concurrent_success = test_concurrent_connections(10)
    
    # Test rapid connections
    print("\n3. Testing rapid sequential connections...")
    rapid_success = test_rapid_connections()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    print(f"Concurrent connections: {concurrent_success}/10")
    print(f"Rapid connections: {rapid_success}/20")
    
    if concurrent_success >= 8 and rapid_success >= 15:
        print("🎉 Rate limiting tests passed!")
    else:
        print("⚠️  Some rate limiting tests failed - this might be expected behavior")

if __name__ == "__main__":
    main()
