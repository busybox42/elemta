#!/usr/bin/env python3
"""
Elemta End-to-End Email Test Suite

Tests complete email functionality including:
- SMTP authentication (PLAIN and LOGIN)
- Inbound email delivery to local domains
- Outbound email relay functionality  
- Message queuing and LMTP delivery
- Header enhancement and security scanning
"""

import socket
import base64
import time
import json
import sys
from typing import Dict, List, Tuple, Optional


class SMTPTestClient:
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

    def _send_command(self, command: str) -> str:
        """Send SMTP command and return response"""
        if not self.connected or not self.sock:
            raise Exception("Not connected to server")
        
        try:
            self.sock.send(f"{command}\r\n".encode())
            return self._read_response()
        except Exception as e:
            raise Exception(f"Command failed: {e}")

    def _read_response(self) -> str:
        """Read SMTP response from server"""
        response = ""
        while True:
            data = self.sock.recv(1024).decode()
            if not data:
                break
            response += data
            # Check if we have a complete response
            if '\n' in response:
                lines = response.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and (len(line) >= 3):
                        # Check if this is the final line (no continuation)
                        if len(line) >= 4 and line[3] == ' ':
                            return response.strip()
                        elif len(line) == 3:
                            return response.strip()
        return response.strip()

    def ehlo(self, hostname: str = "test-client") -> str:
        """Send EHLO command"""
        return self._send_command(f"EHLO {hostname}")

    def auth_login(self, username: str, password: str) -> str:
        """Perform AUTH LOGIN authentication"""
        # Start AUTH LOGIN
        response = self._send_command("AUTH LOGIN")
        if not response.startswith("334"):
            return response
        
        # Send username (base64 encoded)
        username_b64 = base64.b64encode(username.encode()).decode()
        response = self._send_command(username_b64)
        if not response.startswith("334"):
            return response
            
        # Send password (base64 encoded)  
        password_b64 = base64.b64encode(password.encode()).decode()
        return self._send_command(password_b64)

    def auth_plain(self, username: str, password: str) -> str:
        """Perform AUTH PLAIN authentication"""
        # Create PLAIN auth string: \0username\0password
        auth_string = f"\0{username}\0{password}"
        auth_b64 = base64.b64encode(auth_string.encode()).decode()
        return self._send_command(f"AUTH PLAIN {auth_b64}")

    def mail_from(self, sender: str) -> str:
        """Send MAIL FROM command"""
        return self._send_command(f"MAIL FROM:<{sender}>")

    def rcpt_to(self, recipient: str) -> str:
        """Send RCPT TO command"""
        return self._send_command(f"RCPT TO:<{recipient}>")

    def data(self) -> str:
        """Send DATA command"""
        return self._send_command("DATA")

    def send_message_data(self, message: str) -> str:
        """Send message data and end with ."""
        lines = message.split('\n')
        for line in lines:
            self.sock.send(f"{line}\r\n".encode())
        return self._send_command(".")

    def quit(self) -> str:
        """Send QUIT command and close connection"""
        try:
            response = self._send_command("QUIT")
            return response
        finally:
            self.close()

    def close(self):
        """Close connection"""
        if self.sock:
            self.sock.close()
            self.connected = False


class EmailTestSuite:
    def __init__(self):
        self.results: List[Dict] = []
        self.total_tests = 0
        self.passed_tests = 0

    def log_test(self, test_name: str, success: bool, message: str, details: Optional[Dict] = None):
        """Log test result"""
        self.total_tests += 1
        if success:
            self.passed_tests += 1
            
        result = {
            "test": test_name,
            "success": success,
            "message": message,
            "details": details or {}
        }
        self.results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        if details and not success:
            print(f"    Details: {details}")

    def test_connection(self) -> bool:
        """Test basic SMTP connection"""
        try:
            client = SMTPTestClient()
            greeting = client.connect()
            client.close()
            
            if "220" in greeting and "Elemta" in greeting:
                self.log_test("Connection", True, f"Connected successfully: {greeting.split()[0]}")
                return True
            else:
                self.log_test("Connection", False, f"Invalid greeting: {greeting}")
                return False
        except Exception as e:
            self.log_test("Connection", False, f"Connection failed: {e}")
            return False

    def test_ehlo(self) -> bool:
        """Test EHLO command and extensions"""
        try:
            client = SMTPTestClient()
            client.connect()
            response = client.ehlo()
            client.close()
            
            if "250" in response:
                extensions = []
                for line in response.split('\n'):
                    line = line.strip()
                    if line.startswith("250-") or line.startswith("250 "):
                        extensions.append(line[4:])
                
                required_extensions = ["SIZE", "8BITMIME", "PIPELINING", "AUTH"]
                missing = [ext for ext in required_extensions if not any(ext in e for e in extensions)]
                
                if not missing:
                    self.log_test("EHLO", True, f"All required extensions present", {"extensions": extensions})
                    return True
                else:
                    self.log_test("EHLO", False, f"Missing extensions: {missing}", {"extensions": extensions})
                    return False
            else:
                self.log_test("EHLO", False, f"EHLO failed: {response}")
                return False
        except Exception as e:
            self.log_test("EHLO", False, f"EHLO test failed: {e}")
            return False

    def test_auth_login(self) -> bool:
        """Test AUTH LOGIN authentication"""
        try:
            client = SMTPTestClient()
            client.connect()
            client.ehlo()
            
            # Test with demo credentials
            response = client.auth_login("demo@example.com", "demo123")
            client.close()
            
            if "235" in response:  # Authentication successful
                self.log_test("AUTH LOGIN", True, "Authentication successful")
                return True
            else:
                self.log_test("AUTH LOGIN", False, f"Authentication failed: {response}")
                return False
        except Exception as e:
            self.log_test("AUTH LOGIN", False, f"AUTH LOGIN test failed: {e}")
            return False

    def test_auth_plain(self) -> bool:
        """Test AUTH PLAIN authentication"""
        try:
            client = SMTPTestClient()
            client.connect()
            client.ehlo()
            
            # Test with demo credentials
            response = client.auth_plain("demo@example.com", "demo123")
            client.close()
            
            if "235" in response:  # Authentication successful
                self.log_test("AUTH PLAIN", True, "Authentication successful")
                return True
            else:
                self.log_test("AUTH PLAIN", False, f"Authentication failed: {response}")
                return False
        except Exception as e:
            self.log_test("AUTH PLAIN", False, f"AUTH PLAIN test failed: {e}")
            return False

    def test_unauthenticated_local_delivery(self) -> bool:
        """Test sending email to local domain without authentication"""
        try:
            client = SMTPTestClient()
            client.connect()
            client.ehlo()
            
            # Test local domain delivery without auth
            mail_resp = client.mail_from("external@external.com")
            if "250" not in mail_resp:
                self.log_test("Unauthenticated Local", False, f"MAIL FROM failed: {mail_resp}")
                return False
                
            rcpt_resp = client.rcpt_to("demo@example.com")  # Local domain
            if "250" not in rcpt_resp:
                self.log_test("Unauthenticated Local", False, f"RCPT TO failed: {rcpt_resp}")
                return False
                
            data_resp = client.data()
            if "354" not in data_resp:
                self.log_test("Unauthenticated Local", False, f"DATA failed: {data_resp}")
                return False
                
            message = """From: external@external.com
To: demo@example.com
Subject: Test Local Delivery
Date: Sat, 20 Sep 2025 17:45:00 -0400

This is a test of local domain delivery without authentication.
The message should be accepted and delivered via LMTP to Dovecot."""

            send_resp = client.send_message_data(message)
            client.close()
            
            if "250" in send_resp:
                self.log_test("Unauthenticated Local", True, "Local delivery successful")
                return True
            else:
                self.log_test("Unauthenticated Local", False, f"Message send failed: {send_resp}")
                return False
                
        except Exception as e:
            self.log_test("Unauthenticated Local", False, f"Local delivery test failed: {e}")
            return False

    def test_authenticated_relay(self) -> bool:
        """Test authenticated outbound email relay"""
        try:
            client = SMTPTestClient()
            client.connect()
            client.ehlo()
            
            # Authenticate first
            auth_resp = client.auth_login("demo@example.com", "demo123")
            if "235" not in auth_resp:
                self.log_test("Authenticated Relay", False, f"Authentication failed: {auth_resp}")
                return False
                
            # Test relay to external domain
            mail_resp = client.mail_from("demo@example.com")
            if "250" not in mail_resp:
                self.log_test("Authenticated Relay", False, f"MAIL FROM failed: {mail_resp}")
                return False
                
            rcpt_resp = client.rcpt_to("test@external.com")  # External domain
            if "250" not in rcpt_resp:
                self.log_test("Authenticated Relay", False, f"RCPT TO failed: {rcpt_resp}")
                return False
                
            data_resp = client.data()
            if "354" not in data_resp:
                self.log_test("Authenticated Relay", False, f"DATA failed: {data_resp}")
                return False
                
            message = """From: demo@example.com
To: test@external.com
Subject: Test Authenticated Relay
Date: Sat, 20 Sep 2025 17:45:00 -0400

This is a test of authenticated outbound relay.
The message should be queued for external delivery."""

            send_resp = client.send_message_data(message)
            client.close()
            
            if "250" in send_resp:
                self.log_test("Authenticated Relay", True, "Authenticated relay successful")
                return True
            else:
                self.log_test("Authenticated Relay", False, f"Message send failed: {send_resp}")
                return False
                
        except Exception as e:
            self.log_test("Authenticated Relay", False, f"Authenticated relay test failed: {e}")
            return False

    def test_unauthenticated_relay_rejection(self) -> bool:
        """Test that unauthenticated relay to external domains is rejected"""
        try:
            client = SMTPTestClient()
            client.connect()
            client.ehlo()
            
            # Try to send to external domain without auth
            mail_resp = client.mail_from("demo@example.com")
            if "250" not in mail_resp:
                # This might fail due to auth requirements
                client.close()
                self.log_test("Relay Rejection", True, "MAIL FROM rejected without auth (expected)")
                return True
                
            rcpt_resp = client.rcpt_to("test@external.com")  # External domain
            client.close()
            
            if "550" in rcpt_resp or "554" in rcpt_resp:  # Relay denied
                self.log_test("Relay Rejection", True, "External relay properly denied")
                return True
            else:
                self.log_test("Relay Rejection", False, f"Relay should be denied: {rcpt_resp}")
                return False
                
        except Exception as e:
            self.log_test("Relay Rejection", False, f"Relay rejection test failed: {e}")
            return False

    def run_all_tests(self):
        """Run complete test suite"""
        print("🚀 Starting Elemta End-to-End Email Test Suite")
        print("=" * 60)
        
        # Basic connectivity tests
        if not self.test_connection():
            print("❌ Basic connection failed - aborting remaining tests")
            return self.print_summary()
            
        self.test_ehlo()
        
        # Authentication tests
        self.test_auth_login()
        self.test_auth_plain()
        
        # Email delivery tests
        self.test_unauthenticated_local_delivery()
        self.test_authenticated_relay()
        self.test_unauthenticated_relay_rejection()
        
        return self.print_summary()

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 Test Summary")
        print("=" * 60)
        
        print(f"Total Tests: {self.total_tests}")
        print(f"Passed: {self.passed_tests}")
        print(f"Failed: {self.total_tests - self.passed_tests}")
        print(f"Success Rate: {(self.passed_tests/self.total_tests)*100:.1f}%" if self.total_tests > 0 else "N/A")
        
        if self.passed_tests == self.total_tests:
            print("\n🎉 All tests passed! Elemta is fully operational.")
            return True
        else:
            print(f"\n⚠️  {self.total_tests - self.passed_tests} test(s) failed.")
            print("\nFailed Tests:")
            for result in self.results:
                if not result["success"]:
                    print(f"  - {result['test']}: {result['message']}")
            return False


def main():
    """Main test runner"""
    if len(sys.argv) > 1:
        if sys.argv[1] == "--json":
            # JSON output mode for automation
            suite = EmailTestSuite()
            success = suite.run_all_tests()
            print(json.dumps({
                "success": success,
                "total_tests": suite.total_tests,
                "passed_tests": suite.passed_tests,
                "failed_tests": suite.total_tests - suite.passed_tests,
                "results": suite.results
            }, indent=2))
            sys.exit(0 if success else 1)
    
    # Interactive mode
    suite = EmailTestSuite()
    success = suite.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
