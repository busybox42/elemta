#!/usr/bin/env python3
"""
Test script for email content validation and sanitization (ELE-18)
Tests various malicious email content scenarios to ensure proper validation.
"""

import socket
import time
import base64
import sys

class EmailContentValidationTester:
    def __init__(self, host='localhost', port=2525):
        self.host = host
        self.port = port
        self.sock = None
        
    def connect(self):
        """Connect to SMTP server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            
            # Read greeting
            response = self.sock.recv(1024).decode('utf-8')
            if not response.startswith('220'):
                raise Exception(f"Invalid greeting: {response}")
            
            print(f"✅ Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def send_command(self, command):
        """Send SMTP command and read response"""
        if not self.sock:
            return None
            
        try:
            self.sock.send(f"{command}\r\n".encode('utf-8'))
            response = self.sock.recv(1024).decode('utf-8')
            return response.strip()
        except Exception as e:
            print(f"Error sending command '{command}': {e}")
            return None
    
    def send_data(self, data):
        """Send data and read response"""
        if not self.sock:
            return None
            
        try:
            self.sock.send(f"{data}\r\n".encode('utf-8'))
            response = self.sock.recv(1024).decode('utf-8')
            return response.strip()
        except Exception as e:
            print(f"Error sending data: {e}")
            return None
    
    def disconnect(self):
        """Disconnect from server"""
        if self.sock:
            try:
                self.send_command("QUIT")
                self.sock.close()
            except:
                pass
            self.sock = None
    
    def test_sql_injection_in_headers(self):
        """Test SQL injection patterns in email headers"""
        print("\n🔍 Testing SQL injection in headers...")
        
        if not self.connect():
            return False
        
        try:
            # EHLO
            response = self.send_command("EHLO test-client")
            if not response.startswith('250'):
                print(f"❌ EHLO failed: {response}")
                return False
            
            # MAIL FROM
            response = self.send_command("MAIL FROM:<test@example.com>")
            if not response.startswith('250'):
                print(f"❌ MAIL FROM failed: {response}")
                return False
            
            # RCPT TO
            response = self.send_command("RCPT TO:<recipient@example.com>")
            if not response.startswith('250'):
                print(f"❌ RCPT TO failed: {response}")
                return False
            
            # DATA
            response = self.send_command("DATA")
            if not response.startswith('354'):
                print(f"❌ DATA failed: {response}")
                return False
            
            # Send message with SQL injection in headers
            malicious_headers = [
                "From: test@example.com",
                "To: recipient@example.com",
                "Subject: Test SQL Injection",
                "X-Custom: '; DROP TABLE users; --",
                "X-Another: \" OR 1=1 --",
                "",
                "This is a test message with SQL injection in headers.",
                "."
            ]
            
            for line in malicious_headers:
                response = self.send_data(line)
                if response and response.startswith('554'):
                    print(f"✅ SQL injection in headers properly rejected: {response}")
                    return True
            
            # If we get here, the message was accepted (which is bad)
            print("❌ SQL injection in headers was not rejected!")
            return False
            
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            return False
        finally:
            self.disconnect()
    
    def test_script_injection_in_content(self):
        """Test script injection patterns in email content"""
        print("\n🔍 Testing script injection in content...")
        
        if not self.connect():
            return False
        
        try:
            # EHLO
            response = self.send_command("EHLO test-client")
            if not response.startswith('250'):
                print(f"❌ EHLO failed: {response}")
                return False
            
            # MAIL FROM
            response = self.send_command("MAIL FROM:<test@example.com>")
            if not response.startswith('250'):
                print(f"❌ MAIL FROM failed: {response}")
                return False
            
            # RCPT TO
            response = self.send_command("RCPT TO:<recipient@example.com>")
            if not response.startswith('250'):
                print(f"❌ RCPT TO failed: {response}")
                return False
            
            # DATA
            response = self.send_command("DATA")
            if not response.startswith('354'):
                print(f"❌ DATA failed: {response}")
                return False
            
            # Send message with script injection
            malicious_content = [
                "From: test@example.com",
                "To: recipient@example.com",
                "Subject: Test Script Injection",
                "",
                "This is a test message.",
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "."
            ]
            
            for line in malicious_content:
                response = self.send_data(line)
                if response and response.startswith('554'):
                    print(f"✅ Script injection properly rejected: {response}")
                    return True
            
            # If we get here, the message was accepted (which is bad)
            print("❌ Script injection was not rejected!")
            return False
            
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            return False
        finally:
            self.disconnect()
    
    def test_dangerous_attachments(self):
        """Test dangerous attachment types"""
        print("\n🔍 Testing dangerous attachment types...")
        
        if not self.connect():
            return False
        
        try:
            # EHLO
            response = self.send_command("EHLO test-client")
            if not response.startswith('250'):
                print(f"❌ EHLO failed: {response}")
                return False
            
            # MAIL FROM
            response = self.send_command("MAIL FROM:<test@example.com>")
            if not response.startswith('250'):
                print(f"❌ MAIL FROM failed: {response}")
                return False
            
            # RCPT TO
            response = self.send_command("RCPT TO:<recipient@example.com>")
            if not response.startswith('250'):
                print(f"❌ RCPT TO failed: {response}")
                return False
            
            # DATA
            response = self.send_command("DATA")
            if not response.startswith('354'):
                print(f"❌ DATA failed: {response}")
                return False
            
            # Send message with dangerous attachment
            dangerous_attachment = [
                "From: test@example.com",
                "To: recipient@example.com",
                "Subject: Test Dangerous Attachment",
                "Content-Type: multipart/mixed; boundary=boundary123",
                "",
                "--boundary123",
                "Content-Type: text/plain",
                "",
                "This message contains a dangerous attachment.",
                "",
                "--boundary123",
                "Content-Type: application/x-msdownload",
                "Content-Disposition: attachment; filename=malware.exe",
                "",
                "fake executable content",
                "--boundary123--",
                "."
            ]
            
            for line in dangerous_attachment:
                response = self.send_data(line)
                if response and response.startswith('554'):
                    print(f"✅ Dangerous attachment properly rejected: {response}")
                    return True
            
            # If we get here, the message was accepted (which is bad)
            print("❌ Dangerous attachment was not rejected!")
            return False
            
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            return False
        finally:
            self.disconnect()
    
    def test_header_injection(self):
        """Test header injection attacks"""
        print("\n🔍 Testing header injection...")
        
        if not self.connect():
            return False
        
        try:
            # EHLO
            response = self.send_command("EHLO test-client")
            if not response.startswith('250'):
                print(f"❌ EHLO failed: {response}")
                return False
            
            # MAIL FROM
            response = self.send_command("MAIL FROM:<test@example.com>")
            if not response.startswith('250'):
                print(f"❌ MAIL FROM failed: {response}")
                return False
            
            # RCPT TO
            response = self.send_command("RCPT TO:<recipient@example.com>")
            if not response.startswith('250'):
                print(f"❌ RCPT TO failed: {response}")
                return False
            
            # DATA
            response = self.send_command("DATA")
            if not response.startswith('354'):
                print(f"❌ DATA failed: {response}")
                return False
            
            # Send message with header injection
            header_injection = [
                "From: test@example.com",
                "To: recipient@example.com",
                "Subject: Test\r\nX-Injected: malicious header",
                "",
                "This is a test message with header injection.",
                "."
            ]
            
            for line in header_injection:
                response = self.send_data(line)
                if response and response.startswith('554'):
                    print(f"✅ Header injection properly rejected: {response}")
                    return True
            
            # If we get here, the message was accepted (which is bad)
            print("❌ Header injection was not rejected!")
            return False
            
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            return False
        finally:
            self.disconnect()
    
    def test_command_injection(self):
        """Test command injection patterns"""
        print("\n🔍 Testing command injection...")
        
        if not self.connect():
            return False
        
        try:
            # EHLO
            response = self.send_command("EHLO test-client")
            if not response.startswith('250'):
                print(f"❌ EHLO failed: {response}")
                return False
            
            # MAIL FROM
            response = self.send_command("MAIL FROM:<test@example.com>")
            if not response.startswith('250'):
                print(f"❌ MAIL FROM failed: {response}")
                return False
            
            # RCPT TO
            response = self.send_command("RCPT TO:<recipient@example.com>")
            if not response.startswith('250'):
                print(f"❌ RCPT TO failed: {response}")
                return False
            
            # DATA
            response = self.send_command("DATA")
            if not response.startswith('354'):
                print(f"❌ DATA failed: {response}")
                return False
            
            # Send message with command injection
            command_injection = [
                "From: test@example.com",
                "To: recipient@example.com",
                "Subject: Test Command Injection",
                "",
                "This is a test message.",
                "rm -rf /",
                "| cat /etc/passwd",
                "&& whoami",
                "."
            ]
            
            for line in command_injection:
                response = self.send_data(line)
                if response and response.startswith('554'):
                    print(f"✅ Command injection properly rejected: {response}")
                    return True
            
            # If we get here, the message was accepted (which is bad)
            print("❌ Command injection was not rejected!")
            return False
            
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            return False
        finally:
            self.disconnect()
    
    def test_legitimate_email(self):
        """Test that legitimate emails are accepted"""
        print("\n🔍 Testing legitimate email acceptance...")
        
        if not self.connect():
            return False
        
        try:
            # EHLO
            response = self.send_command("EHLO test-client")
            if not response.startswith('250'):
                print(f"❌ EHLO failed: {response}")
                return False
            
            # MAIL FROM
            response = self.send_command("MAIL FROM:<test@example.com>")
            if not response.startswith('250'):
                print(f"❌ MAIL FROM failed: {response}")
                return False
            
            # RCPT TO
            response = self.send_command("RCPT TO:<recipient@example.com>")
            if not response.startswith('250'):
                print(f"❌ RCPT TO failed: {response}")
                return False
            
            # DATA
            response = self.send_command("DATA")
            if not response.startswith('354'):
                print(f"❌ DATA failed: {response}")
                return False
            
            # Send legitimate message
            legitimate_message = [
                "From: test@example.com",
                "To: recipient@example.com",
                "Subject: Legitimate Test Message",
                "Content-Type: text/plain; charset=utf-8",
                "",
                "This is a legitimate test message.",
                "It contains normal content without any malicious patterns.",
                "The server should accept this message.",
                "."
            ]
            
            for line in legitimate_message:
                response = self.send_data(line)
                if response and response.startswith('250'):
                    print(f"✅ Legitimate email properly accepted: {response}")
                    return True
                elif response and response.startswith('554'):
                    print(f"❌ Legitimate email was rejected: {response}")
                    return False
            
            print("❌ No response received for legitimate email")
            return False
            
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            return False
        finally:
            self.disconnect()

def main():
    print("🚀 Starting Email Content Validation Test Suite")
    print("=" * 60)
    
    tester = EmailContentValidationTester()
    
    tests = [
        ("SQL Injection in Headers", tester.test_sql_injection_in_headers),
        ("Script Injection in Content", tester.test_script_injection_in_content),
        ("Dangerous Attachments", tester.test_dangerous_attachments),
        ("Header Injection", tester.test_header_injection),
        ("Command Injection", tester.test_command_injection),
        ("Legitimate Email", tester.test_legitimate_email),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n📋 Running: {test_name}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                failed += 1
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            failed += 1
            print(f"❌ {test_name}: FAILED with exception: {e}")
    
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    print(f"Total Tests: {passed + failed}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed / (passed + failed) * 100):.1f}%")
    
    if failed == 0:
        print("🎉 All tests passed! Email content validation is working correctly.")
        return 0
    else:
        print(f"⚠️  {failed} test(s) failed. Email content validation needs attention.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
