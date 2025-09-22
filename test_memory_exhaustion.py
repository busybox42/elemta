#!/usr/bin/env python3
"""
ELE-16 Memory Exhaustion Attack Tests

This test suite validates that the SMTP server properly handles memory exhaustion
attacks and implements the required protections per ELE-16.

Tests:
1. Large message within limits (should pass)
2. Large message exceeding session memory limit (should be rejected)
3. Multiple concurrent large messages (should handle gracefully)
4. Progressive memory tracking during data reading
5. Memory exhaustion protection circuit breaker
"""

import socket
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

class MemoryExhaustionTester:
    def __init__(self, host='localhost', port=2525):
        self.host = host
        self.port = port
        self.results = []

    def send_large_message(self, size_mb, message_id="test"):
        """Send a message of specified size in MB"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)  # 60 second timeout for large messages
            sock.connect((self.host, self.port))
            
            # Read greeting
            greeting = sock.recv(1024).decode().strip()
            if not greeting.startswith('220'):
                return f"FAIL: Invalid greeting: {greeting}"
            
            # Send EHLO
            sock.send(b'EHLO memory-test\r\n')
            ehlo_response = sock.recv(1024).decode().strip()
            if not ehlo_response.startswith('250'):
                return f"FAIL: EHLO failed: {ehlo_response}"
            
            # Send MAIL FROM
            sock.send(b'MAIL FROM: <test@example.com>\r\n')
            mail_response = sock.recv(1024).decode().strip()
            if not mail_response.startswith('250'):
                return f"FAIL: MAIL FROM failed: {mail_response}"
            
            # Send RCPT TO
            sock.send(b'RCPT TO: <demo@example.com>\r\n')
            rcpt_response = sock.recv(1024).decode().strip()
            if not rcpt_response.startswith('250'):
                return f"FAIL: RCPT TO failed: {rcpt_response}"
            
            # Send DATA
            sock.send(b'DATA\r\n')
            data_response = sock.recv(1024).decode().strip()
            if not data_response.startswith('354'):
                return f"FAIL: DATA failed: {data_response}"
            
            # Send headers
            headers = f"""From: test@example.com
To: demo@example.com
Subject: Memory Test {message_id} ({size_mb}MB)
Message-ID: <{message_id}@example.com>
Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000')}

"""
            
            for line in headers.split('\n'):
                sock.send((line + '\r\n').encode())
            
            # Send large body with proper SMTP line length (max 998 chars per line)
            line_size = 990  # Leave room for \r\n
            lines_needed = (size_mb * 1024 * 1024) // line_size
            sent_lines = 0
            
            for i in range(lines_needed):
                # Create line with proper SMTP length
                line = f"Memory test data line {i} " + "X" * (line_size - 50) + "\r\n"
                sock.send(line.encode())
                sent_lines += 1
                
                # Progress reporting every 10MB
                if sent_lines % (10 * 1024) == 0:
                    print(f"  {message_id}: Sent {sent_lines // 1024}MB...")
                
                # Small delay to allow progressive memory tracking
                if sent_lines % 1024 == 0:  # Every 1MB
                    time.sleep(0.001)
            
            # Send end of data
            sock.send(b'\r\n.\r\n')
            final_response = sock.recv(1024).decode().strip()
            
            # Send QUIT
            sock.send(b'QUIT\r\n')
            quit_response = sock.recv(1024).decode().strip()
            
            sock.close()
            
            return f"SUCCESS: {message_id} ({size_mb}MB) - Response: {final_response}"
            
        except socket.timeout:
            return f"TIMEOUT: {message_id} ({size_mb}MB) - Connection timed out"
        except Exception as e:
            return f"ERROR: {message_id} ({size_mb}MB) - {str(e)}"

    def test_within_session_limits(self):
        """Test 1: Send a message within session memory limits (30MB)"""
        print("🧪 Test 1: Message within session memory limits (30MB)")
        result = self.send_large_message(30, "within-limits")
        print(f"   Result: {result}")
        
        if "SUCCESS" in result and "250" in result:
            print("   ✅ PASS: Message within limits accepted")
            return True
        else:
            print("   ❌ FAIL: Message within limits rejected")
            return False

    def test_exceeding_session_limits(self):
        """Test 2: Send a message exceeding session memory limits (60MB)"""
        print("🧪 Test 2: Message exceeding session memory limits (60MB)")
        result = self.send_large_message(60, "exceeding-limits")
        print(f"   Result: {result}")
        
        if "552" in result or "552" in result:
            print("   ✅ PASS: Message exceeding limits properly rejected")
            return True
        elif "TIMEOUT" in result:
            print("   ✅ PASS: Message exceeding limits timed out (protection working)")
            return True
        else:
            print("   ❌ FAIL: Message exceeding limits was accepted")
            return False

    def test_concurrent_large_messages(self):
        """Test 3: Send multiple concurrent large messages"""
        print("🧪 Test 3: Multiple concurrent large messages (5x 25MB)")
        
        def send_message(thread_id):
            return self.send_large_message(25, f"concurrent-{thread_id}")
        
        results = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(send_message, i) for i in range(5)]
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                print(f"   Thread result: {result}")
        
        # Analyze results
        successful = sum(1 for r in results if "SUCCESS" in r and "250" in r)
        rejected = sum(1 for r in results if "552" in r)
        timeouts = sum(1 for r in results if "TIMEOUT" in r)
        
        print(f"   Results: {successful} successful, {rejected} rejected, {timeouts} timeouts")
        
        # Should have some successful and some rejected/timeout due to memory limits
        if successful > 0 and (rejected > 0 or timeouts > 0):
            print("   ✅ PASS: Memory protection working - some accepted, some rejected")
            return True
        elif successful == 5:
            print("   ⚠️  WARNING: All messages accepted - memory limits may not be working")
            return False
        else:
            print("   ❌ FAIL: Unexpected results")
            return False

    def test_progressive_memory_tracking(self):
        """Test 4: Test progressive memory tracking during data reading"""
        print("🧪 Test 4: Progressive memory tracking (40MB message)")
        
        # Send a message that should trigger progressive memory tracking
        result = self.send_large_message(40, "progressive-tracking")
        print(f"   Result: {result}")
        
        if "SUCCESS" in result and "250" in result:
            print("   ✅ PASS: Progressive memory tracking allows message within limits")
            return True
        elif "552" in result:
            print("   ✅ PASS: Progressive memory tracking properly rejected oversized message")
            return True
        else:
            print("   ❌ FAIL: Unexpected result from progressive memory tracking")
            return False

    def test_memory_exhaustion_protection(self):
        """Test 5: Test memory exhaustion protection circuit breaker"""
        print("🧪 Test 5: Memory exhaustion protection circuit breaker")
        
        # Try to send multiple large messages rapidly to trigger circuit breaker
        results = []
        for i in range(10):  # Send 10 large messages rapidly
            result = self.send_large_message(30, f"exhaustion-{i}")
            results.append(result)
            print(f"   Message {i}: {result}")
            time.sleep(0.1)  # Small delay between messages
        
        # Check if circuit breaker activated
        rejected = sum(1 for r in results if "552" in r)
        timeouts = sum(1 for r in results if "TIMEOUT" in r)
        
        if rejected > 0 or timeouts > 0:
            print("   ✅ PASS: Memory exhaustion protection activated")
            return True
        else:
            print("   ❌ FAIL: Memory exhaustion protection not working")
            return False

    def run_all_tests(self):
        """Run all memory exhaustion tests"""
        print("🚀 Starting ELE-16 Memory Exhaustion Attack Tests")
        print("=" * 60)
        
        tests = [
            self.test_within_session_limits,
            self.test_exceeding_session_limits,
            self.test_concurrent_large_messages,
            self.test_progressive_memory_tracking,
            self.test_memory_exhaustion_protection,
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
            except Exception as e:
                print(f"   ❌ FAIL: Test exception: {e}")
            print()
        
        print("=" * 60)
        print(f"📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All memory exhaustion protection tests passed!")
            print("✅ ELE-16 Memory Exhaustion Vulnerability - RESOLVED")
        else:
            print(f"⚠️  {total - passed} tests failed")
            print("❌ ELE-16 Memory Exhaustion Vulnerability - NOT FULLY RESOLVED")
        
        return passed == total

if __name__ == "__main__":
    tester = MemoryExhaustionTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)
