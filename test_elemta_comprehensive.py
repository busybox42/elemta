#!/usr/bin/env python3
"""
Elemta Comprehensive Test Suite

This script consolidates all Elemta SMTP server tests into a single, 
configurable test runner. It can run all tests or specific test categories.

Usage:
    python3 test_elemta_comprehensive.py                    # Run all tests
    python3 test_elemta_comprehensive.py --category basic   # Run only basic tests
    python3 test_elemta_comprehensive.py --category security # Run only security tests
    python3 test_elemta_comprehensive.py --test smtp        # Run specific test
    python3 test_elemta_comprehensive.py --help             # Show help

Test Categories:
    - basic: Core SMTP functionality (EHLO, MAIL, RCPT, DATA, QUIT)
    - auth: Authentication tests (PLAIN, LOGIN)
    - security: Security tests (buffer overflow, injection, validation)
    - content: Email content validation and sanitization
    - memory: Memory exhaustion and resource management
    - rate: Rate limiting and connection management
    - logging: Email logging and monitoring
    - integration: End-to-end email delivery tests
"""

import socket
import base64
import time
import json
import sys
import argparse
import threading
import random
import string
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass
from enum import Enum

class TestResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"

@dataclass
class TestCase:
    name: str
    category: str
    description: str
    test_func: Callable
    required: bool = True

class SMTPTestClient:
    """Unified SMTP test client for all test categories"""
    
    def __init__(self, host: str = "localhost", port: int = 2525, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.connected = False

    def connect(self) -> str:
        """Connect to SMTP server and return greeting"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect((self.host, self.port))
            greeting = self._read_response()
            self.connected = True
            return greeting
        except Exception as e:
            if self.sock:
                self.sock.close()
            raise Exception(f"Connection failed: {e}")

    def disconnect(self):
        """Disconnect from SMTP server"""
        if self.sock:
            try:
                self.sock.send(b"QUIT\r\n")
                self._read_response()
            except:
                pass
            self.sock.close()
            self.connected = False

    def _read_response(self) -> str:
        """Read SMTP response"""
        response = self.sock.recv(1024).decode('utf-8', errors='ignore')
        return response.strip()

    def send_command(self, command: str) -> str:
        """Send SMTP command and return response"""
        if not self.connected or not self.sock:
            raise Exception("Not connected to server")
        
        try:
            self.sock.send(f"{command}\r\n".encode())
            return self._read_response()
        except Exception as e:
            raise Exception(f"Command failed: {e}")

    def send_data(self, data: str) -> str:
        """Send data and return response"""
        if not self.connected or not self.sock:
            raise Exception("Not connected to server")
        
        try:
            self.sock.send(f"{data}\r\n".encode())
            return self._read_response()
        except Exception as e:
            raise Exception(f"Data send failed: {e}")

class ElemtaTestSuite:
    """Main test suite class"""
    
    def __init__(self, host: str = "localhost", port: int = 2525):
        self.host = host
        self.port = port
        self.test_results: List[Tuple[str, TestResult, str]] = []
        self.test_cases: List[TestCase] = []
        self._register_tests()

    def _register_tests(self):
        """Register all test cases"""
        
        # Basic SMTP Tests
        self.test_cases.extend([
            TestCase("smtp_greeting", "basic", "SMTP server greeting", self._test_smtp_greeting),
            TestCase("smtp_ehlo", "basic", "EHLO command", self._test_smtp_ehlo),
            TestCase("smtp_mail_rcpt", "basic", "MAIL FROM and RCPT TO", self._test_smtp_mail_rcpt),
            TestCase("smtp_data", "basic", "DATA command and message", self._test_smtp_data),
            TestCase("smtp_quit", "basic", "QUIT command", self._test_smtp_quit),
        ])
        
        # Authentication Tests
        self.test_cases.extend([
            TestCase("auth_plain", "auth", "AUTH PLAIN mechanism", self._test_auth_plain),
            TestCase("auth_login", "auth", "AUTH LOGIN mechanism", self._test_auth_login),
            TestCase("auth_invalid", "auth", "Invalid authentication", self._test_auth_invalid),
        ])
        
        # Security Tests
        self.test_cases.extend([
            TestCase("security_buffer_overflow", "security", "Buffer overflow protection", self._test_buffer_overflow),
            TestCase("security_sql_injection", "security", "SQL injection protection", self._test_sql_injection),
            TestCase("security_command_injection", "security", "Command injection protection", self._test_command_injection),
            TestCase("security_xss", "security", "XSS protection", self._test_xss_protection),
            TestCase("security_null_bytes", "security", "Null byte protection", self._test_null_bytes),
            TestCase("security_long_commands", "security", "Long command protection", self._test_long_commands),
        ])
        
        # Content Validation Tests
        self.test_cases.extend([
            TestCase("content_legitimate", "content", "Legitimate email content", self._test_legitimate_content),
            TestCase("content_malicious_headers", "content", "Malicious header detection", self._test_malicious_headers),
            TestCase("content_dangerous_attachments", "content", "Dangerous attachment detection", self._test_dangerous_attachments),
            TestCase("content_unicode_attacks", "content", "Unicode attack detection", self._test_unicode_attacks),
        ])
        
        # Memory Tests
        self.test_cases.extend([
            TestCase("memory_large_message", "memory", "Large message handling", self._test_large_message),
            TestCase("memory_concurrent_connections", "memory", "Concurrent connection handling", self._test_concurrent_connections),
            TestCase("memory_rapid_commands", "memory", "Rapid command handling", self._test_rapid_commands),
        ])
        
        # Rate Limiting Tests
        self.test_cases.extend([
            TestCase("rate_connection_limits", "rate", "Connection rate limiting", self._test_connection_limits),
            TestCase("rate_message_limits", "rate", "Message rate limiting", self._test_message_limits),
        ])
        
        # Logging Tests
        self.test_cases.extend([
            TestCase("logging_email_events", "logging", "Email event logging", self._test_email_logging),
            TestCase("logging_security_events", "logging", "Security event logging", self._test_security_logging),
        ])
        
        # Integration Tests
        self.test_cases.extend([
            TestCase("integration_end_to_end", "integration", "End-to-end email delivery", self._test_end_to_end),
            TestCase("integration_queue_processing", "integration", "Queue processing", self._test_queue_processing),
        ])

    def run_tests(self, categories: List[str] = None, specific_tests: List[str] = None) -> Dict[str, int]:
        """Run tests based on categories or specific test names"""
        
        # Filter test cases
        tests_to_run = []
        if specific_tests:
            tests_to_run = [tc for tc in self.test_cases if tc.name in specific_tests]
        elif categories:
            tests_to_run = [tc for tc in self.test_cases if tc.category in categories]
        else:
            tests_to_run = self.test_cases
        
        if not tests_to_run:
            print("❌ No tests found matching criteria")
            return {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
        
        print(f"🚀 Running {len(tests_to_run)} tests...")
        print("=" * 60)
        
        # Run tests
        for test_case in tests_to_run:
            try:
                print(f"🔍 Testing {test_case.name}: {test_case.description}")
                result = test_case.test_func()
                self.test_results.append((test_case.name, result, ""))
                
                if result == TestResult.PASS:
                    print(f"✅ PASS {test_case.name}")
                elif result == TestResult.FAIL:
                    print(f"❌ FAIL {test_case.name}")
                else:
                    print(f"⏭️  SKIP {test_case.name}")
                    
            except Exception as e:
                print(f"❌ ERROR {test_case.name}: {e}")
                self.test_results.append((test_case.name, TestResult.FAIL, str(e)))
        
        # Print summary
        return self._print_summary()
    
    def _print_summary(self) -> Dict[str, int]:
        """Print test summary and return statistics"""
        total = len(self.test_results)
        passed = sum(1 for _, result, _ in self.test_results if result == TestResult.PASS)
        failed = sum(1 for _, result, _ in self.test_results if result == TestResult.FAIL)
        skipped = sum(1 for _, result, _ in self.test_results if result == TestResult.SKIP)
        
        print("\n" + "=" * 60)
        print("📊 Test Summary:")
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Skipped: {skipped}")
        print(f"Success Rate: {(passed/total*100):.1f}%" if total > 0 else "N/A")
        
        if failed > 0:
            print(f"\n⚠️  {failed} tests failed. Review the results above.")
        else:
            print(f"\n🎉 All tests passed!")
        
        return {"total": total, "passed": passed, "failed": failed, "skipped": skipped}

    # ============================================================================
    # BASIC SMTP TESTS
    # ============================================================================
    
    def _test_smtp_greeting(self) -> TestResult:
        """Test SMTP server greeting"""
        try:
            client = SMTPTestClient(self.host, self.port)
            greeting = client.connect()
            client.disconnect()
            
            if greeting.startswith("220"):
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_smtp_ehlo(self) -> TestResult:
        """Test EHLO command"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            response = client.send_command("EHLO test.com")
            client.disconnect()
            
            if response.startswith("250"):
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_smtp_mail_rcpt(self) -> TestResult:
        """Test MAIL FROM and RCPT TO commands"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            
            # Test MAIL FROM
            response = client.send_command("MAIL FROM:<test@example.com>")
            if not response.startswith("250"):
                client.disconnect()
                return TestResult.FAIL
            
            # Test RCPT TO
            response = client.send_command("RCPT TO:<recipient@example.com>")
            if not response.startswith("250"):
                client.disconnect()
                return TestResult.FAIL
            
            client.disconnect()
            return TestResult.PASS
        except:
            return TestResult.FAIL
    
    def _test_smtp_data(self) -> TestResult:
        """Test DATA command and message sending"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            client.send_command("MAIL FROM:<test@example.com>")
            client.send_command("RCPT TO:<recipient@example.com>")
            
            # Test DATA
            response = client.send_command("DATA")
            if not response.startswith("354"):
                client.disconnect()
                return TestResult.FAIL
            
            # Send message
            message = "Subject: Test\r\n\r\nThis is a test message.\r\n."
            response = client.send_command(message)
            if not response.startswith("250"):
                client.disconnect()
                return TestResult.FAIL
            
            client.disconnect()
            return TestResult.PASS
        except:
            return TestResult.FAIL
    
    def _test_smtp_quit(self) -> TestResult:
        """Test QUIT command"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            response = client.send_command("QUIT")
            client.disconnect()
            
            if response.startswith("221"):
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL

    # ============================================================================
    # AUTHENTICATION TESTS
    # ============================================================================
    
    def _test_auth_plain(self) -> TestResult:
        """Test AUTH PLAIN mechanism"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            
            # Test AUTH PLAIN
            response = client.send_command("AUTH PLAIN")
            if not response.startswith("334"):
                client.disconnect()
                return TestResult.FAIL
            
            # Send credentials (demo@example.com:demo123)
            credentials = base64.b64encode(b"\x00demo@example.com\x00demo123").decode()
            response = client.send_command(credentials)
            client.disconnect()
            
            if response.startswith("235"):
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_auth_login(self) -> TestResult:
        """Test AUTH LOGIN mechanism"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            
            # Test AUTH LOGIN
            response = client.send_command("AUTH LOGIN")
            if not response.startswith("334"):
                client.disconnect()
                return TestResult.FAIL
            
            # Send username
            username = base64.b64encode(b"demo@example.com").decode()
            response = client.send_command(username)
            if not response.startswith("334"):
                client.disconnect()
                return TestResult.FAIL
            
            # Send password
            password = base64.b64encode(b"demo123").decode()
            response = client.send_command(password)
            client.disconnect()
            
            if response.startswith("235"):
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_auth_invalid(self) -> TestResult:
        """Test invalid authentication"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            
            # Test AUTH PLAIN with invalid credentials
            response = client.send_command("AUTH PLAIN")
            if not response.startswith("334"):
                client.disconnect()
                return TestResult.FAIL
            
            # Send invalid credentials
            credentials = base64.b64encode(b"\x00invalid@example.com\x00wrongpass").decode()
            response = client.send_command(credentials)
            client.disconnect()
            
            # Should fail authentication
            if response.startswith("535"):
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL

    # ============================================================================
    # SECURITY TESTS
    # ============================================================================
    
    def _test_buffer_overflow(self) -> TestResult:
        """Test buffer overflow protection"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            
            # Test long command
            long_cmd = 'A' * 1000
            response = client.send_command(long_cmd)
            client.disconnect()
            
            if "Line too long" in response:
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_sql_injection(self) -> TestResult:
        """Test SQL injection protection"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            
            # Test SQL injection in HELO
            response = client.send_command("HELO'; DROP TABLE users; --")
            client.disconnect()
            
            if "Invalid command name" in response or "500" in response:
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_command_injection(self) -> TestResult:
        """Test command injection protection"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            
            # Test command injection
            response = client.send_command("HELO test.com; rm -rf /")
            client.disconnect()
            
            if "Invalid command name" in response or "500" in response:
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_xss_protection(self) -> TestResult:
        """Test XSS protection"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            
            # Test XSS in HELO
            response = client.send_command("HELO <script>alert('xss')</script>")
            client.disconnect()
            
            if "Invalid command name" in response or "500" in response:
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_null_bytes(self) -> TestResult:
        """Test null byte protection"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            
            # Test null bytes
            response = client.send_command("HELO\x00test.com")
            client.disconnect()
            
            if "Invalid control character" in response:
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_long_commands(self) -> TestResult:
        """Test long command protection"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            
            # Test long email address
            long_email = "A" * 500 + "@example.com"
            response = client.send_command(f"MAIL FROM:<{long_email}>")
            client.disconnect()
            
            if "Line too long" in response:
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL

    # ============================================================================
    # CONTENT VALIDATION TESTS
    # ============================================================================
    
    def _test_legitimate_content(self) -> TestResult:
        """Test legitimate email content acceptance"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            client.send_command("MAIL FROM:<test@example.com>")
            client.send_command("RCPT TO:<recipient@example.com>")
            client.send_command("DATA")
            
            # Send legitimate message
            message = "Subject: Test Message\r\nFrom: test@example.com\r\nTo: recipient@example.com\r\n\r\nThis is a legitimate test message.\r\n."
            response = client.send_command(message)
            client.disconnect()
            
            if response.startswith("250"):
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_malicious_headers(self) -> TestResult:
        """Test malicious header detection"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            client.send_command("MAIL FROM:<test@example.com>")
            client.send_command("RCPT TO:<recipient@example.com>")
            client.send_command("DATA")
            
            # Send message with malicious headers
            message = "Subject: Test\r\nBcc: victim@target.com\r\n\r\nThis message has malicious headers.\r\n."
            response = client.send_command(message)
            client.disconnect()
            
            # Should be rejected or flagged
            if "rejected" in response.lower() or "invalid" in response.lower():
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_dangerous_attachments(self) -> TestResult:
        """Test dangerous attachment detection"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            client.send_command("MAIL FROM:<test@example.com>")
            client.send_command("RCPT TO:<recipient@example.com>")
            client.send_command("DATA")
            
            # Send message with dangerous attachment
            message = "Subject: Test\r\nContent-Type: application/x-executable\r\n\r\nThis message has a dangerous attachment.\r\n."
            response = client.send_command(message)
            client.disconnect()
            
            # Should be rejected or flagged
            if "rejected" in response.lower() or "invalid" in response.lower():
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_unicode_attacks(self) -> TestResult:
        """Test Unicode attack detection"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            client.send_command("MAIL FROM:<test@example.com>")
            client.send_command("RCPT TO:<recipient@example.com>")
            client.send_command("DATA")
            
            # Send message with Unicode attacks
            message = "Subject: Test\r\n\r\nThis message contains suspicious Unicode: аpple.com\r\n."
            response = client.send_command(message)
            client.disconnect()
            
            # Should be rejected or flagged
            if "rejected" in response.lower() or "invalid" in response.lower():
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL

    # ============================================================================
    # MEMORY TESTS
    # ============================================================================
    
    def _test_large_message(self) -> TestResult:
        """Test large message handling"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            client.send_command("MAIL FROM:<test@example.com>")
            client.send_command("RCPT TO:<recipient@example.com>")
            client.send_command("DATA")
            
            # Send large message (1MB)
            large_content = "A" * (1024 * 1024)
            message = f"Subject: Large Test\r\n\r\n{large_content}\r\n."
            response = client.send_command(message)
            client.disconnect()
            
            # Should handle gracefully (either accept or reject with proper error)
            if response.startswith("250") or "too large" in response.lower():
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_concurrent_connections(self) -> TestResult:
        """Test concurrent connection handling"""
        try:
            results = []
            
            def test_connection():
                try:
                    client = SMTPTestClient(self.host, self.port)
                    client.connect()
                    client.send_command("EHLO test.com")
                    client.send_command("QUIT")
                    client.disconnect()
                    results.append(True)
                except:
                    results.append(False)
            
            # Create 5 concurrent connections
            threads = []
            for _ in range(5):
                thread = threading.Thread(target=test_connection)
                threads.append(thread)
                thread.start()
            
            # Wait for all threads
            for thread in threads:
                thread.join()
            
            # Check if all connections succeeded
            if all(results) and len(results) == 5:
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_rapid_commands(self) -> TestResult:
        """Test rapid command handling"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            
            # Send rapid commands
            for i in range(10):
                response = client.send_command("NOOP")
                if not response.startswith("250"):
                    client.disconnect()
                    return TestResult.FAIL
            
            client.disconnect()
            return TestResult.PASS
        except:
            return TestResult.FAIL

    # ============================================================================
    # RATE LIMITING TESTS
    # ============================================================================
    
    def _test_connection_limits(self) -> TestResult:
        """Test connection rate limiting"""
        # This is a placeholder - rate limiting tests would go here
        # For now, we'll skip this test as the rate limiter plugin isn't fully implemented
        return TestResult.SKIP
    
    def _test_message_limits(self) -> TestResult:
        """Test message rate limiting"""
        # This is a placeholder - rate limiting tests would go here
        # For now, we'll skip this test as the rate limiter plugin isn't fully implemented
        return TestResult.SKIP

    # ============================================================================
    # LOGGING TESTS
    # ============================================================================
    
    def _test_email_logging(self) -> TestResult:
        """Test email event logging"""
        # This is a placeholder - logging tests would go here
        # For now, we'll skip this test as it requires log analysis
        return TestResult.SKIP
    
    def _test_security_logging(self) -> TestResult:
        """Test security event logging"""
        # This is a placeholder - security logging tests would go here
        # For now, we'll skip this test as it requires log analysis
        return TestResult.SKIP

    # ============================================================================
    # INTEGRATION TESTS
    # ============================================================================
    
    def _test_end_to_end(self) -> TestResult:
        """Test end-to-end email delivery"""
        try:
            client = SMTPTestClient(self.host, self.port)
            client.connect()
            client.send_command("EHLO test.com")
            client.send_command("MAIL FROM:<test@example.com>")
            client.send_command("RCPT TO:<recipient@example.com>")
            client.send_command("DATA")
            
            # Send complete email
            message = "Subject: End-to-End Test\r\nFrom: test@example.com\r\nTo: recipient@example.com\r\n\r\nThis is an end-to-end test message.\r\n."
            response = client.send_command(message)
            client.disconnect()
            
            if response.startswith("250"):
                return TestResult.PASS
            else:
                return TestResult.FAIL
        except:
            return TestResult.FAIL
    
    def _test_queue_processing(self) -> TestResult:
        """Test queue processing"""
        # This is a placeholder - queue processing tests would go here
        # For now, we'll skip this test as it requires queue analysis
        return TestResult.SKIP

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Elemta Comprehensive Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 test_elemta_comprehensive.py                    # Run all tests
  python3 test_elemta_comprehensive.py --category basic   # Run only basic tests
  python3 test_elemta_comprehensive.py --category security # Run only security tests
  python3 test_elemta_comprehensive.py --test smtp_greeting # Run specific test
  python3 test_elemta_comprehensive.py --host 192.168.1.100 # Test remote server
        """
    )
    
    parser.add_argument("--host", default="localhost", help="SMTP server host (default: localhost)")
    parser.add_argument("--port", type=int, default=2525, help="SMTP server port (default: 2525)")
    parser.add_argument("--category", action="append", help="Test category to run (can be specified multiple times)")
    parser.add_argument("--test", action="append", help="Specific test to run (can be specified multiple times)")
    parser.add_argument("--list", action="store_true", help="List all available tests")
    
    args = parser.parse_args()
    
    # Create test suite
    test_suite = ElemtaTestSuite(args.host, args.port)
    
    # List tests if requested
    if args.list:
        print("Available Test Categories:")
        categories = set(tc.category for tc in test_suite.test_cases)
        for category in sorted(categories):
            print(f"\n{category.upper()}:")
            for tc in test_suite.test_cases:
                if tc.category == category:
                    print(f"  - {tc.name}: {tc.description}")
        return
    
    # Run tests
    try:
        stats = test_suite.run_tests(args.category, args.test)
        
        # Exit with appropriate code
        if stats["failed"] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n⚠️  Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Test suite error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
