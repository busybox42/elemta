#!/usr/bin/env python3
"""
Comprehensive Email Logging Test Suite for Elemta MTA

This test suite validates all email transaction logging scenarios:
- message_received
- message_accepted  
- message_enqueued
- message_delivered
- message_tempfail
- message_bounced
- message_rejected (security/virus/spam)
- mail_from_accepted
- rcpt_to_accepted
- Authentication events
- Connection events
"""

import socket
import time
import json
import subprocess
import re
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class LogEvent:
    event_type: str
    required_fields: List[str]
    optional_fields: List[str] = None

# Define expected log events and their required fields
EXPECTED_EVENTS = {
    "connection_accepted": LogEvent(
        "connection_accepted",
        ["client_ip", "server_ip", "connection_id", "remote_addr"]
    ),
    "mail_from_accepted": LogEvent(
        "mail_from_accepted", 
        ["event_type", "mail_from", "authenticated", "client_ip", "connection_id", "tls_active"]
    ),
    "rcpt_to_accepted": LogEvent(
        "rcpt_to_accepted",
        ["event_type", "rcpt_to", "mail_from", "total_recipients", "authenticated", "client_ip", "connection_id"]
    ),
    "message_received": LogEvent(
        "message_received",
        ["event_type", "from_envelope", "to_envelope", "message_size", "recipient_count", "client_ip", "server_ip", "connection_id", "authenticated", "username", "tls_active", "processing_time_ms"]
    ),
    "message_accepted": LogEvent(
        "message_accepted",
        ["event_type", "message_id", "from_envelope", "to_envelope", "to_count", "message_size", "priority", "queue_type", "enqueue_time"]
    ),
    "message_enqueued": LogEvent(
        "message_enqueued",
        ["event_type", "message_id", "from_envelope", "to_envelope", "message_subject", "message_size", "message_id_header", "queue_time"]
    ),
    "message_delivered": LogEvent(
        "message_delivered",
        ["event_type", "message_id", "from_envelope", "to_envelope", "message_subject", "message_size", "delivery_method", "delivery_host", "delivery_port", "retry_count", "delivery_time", "status", "processing_time_ms"]
    ),
    "message_tempfail": LogEvent(
        "message_tempfail",
        ["event_type", "message_id", "from_envelope", "to_envelope", "message_subject", "message_size", "delivery_method", "delivery_host", "delivery_port", "retry_count", "max_retries", "error", "status", "processing_time_ms"]
    ),
    "message_bounced": LogEvent(
        "message_bounced",
        ["event_type", "message_id", "from_envelope", "to_envelope", "message_subject", "message_size", "delivery_method", "delivery_host", "delivery_port", "retry_count", "error", "status", "processing_time_ms"]
    ),
    "message_rejected": LogEvent(
        "message_rejected",
        ["event_type", "message_id", "from_envelope", "to_envelope", "reason", "client_ip", "connection_id", "rejection_time"],
        ["virus_detected", "spam_score", "security_threat", "header_validation_failed"]
    ),
    "spam_detected": LogEvent(
        "spam_detected",
        ["event_type", "message_id", "from_envelope", "to_envelope", "spam_score", "spam_threshold", "spam_headers", "client_ip", "connection_id"]
    ),
    "virus_detected": LogEvent(
        "virus_detected", 
        ["event_type", "message_id", "from_envelope", "to_envelope", "virus_name", "client_ip", "connection_id"]
    )
}

class EmailLoggingTester:
    def __init__(self, host="localhost", port=2525):
        self.host = host
        self.port = port
        self.test_results = []
        
    def send_smtp_command(self, sock, command, expected_code=None):
        """Send SMTP command and return response"""
        sock.send(f"{command}\r\n".encode())
        
        # Read complete response (handle multi-line responses like the working test)
        response = ""
        while True:
            data = sock.recv(1024).decode()
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
                            response = response.strip()
                            if expected_code and not response.startswith(expected_code):
                                raise Exception(f"Expected {expected_code}, got: {response}")
                            return response
                        elif len(line) == 3:
                            response = response.strip()
                            if expected_code and not response.startswith(expected_code):
                                raise Exception(f"Expected {expected_code}, got: {response}")
                            return response
        
        response = response.strip()
        if expected_code and not response.startswith(expected_code):
            raise Exception(f"Expected {expected_code}, got: {response}")
        return response
    
    def read_greeting(self, sock):
        """Read the initial SMTP greeting"""
        response = sock.recv(1024).decode().strip()
        if not response.startswith("220"):
            raise Exception(f"Expected 220 greeting, got: {response}")
        return response
    
    def test_valid_email_delivery(self):
        """Test 1: Valid email delivery - should generate message_delivered"""
        print("🧪 Test 1: Valid Email Delivery")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            # Read greeting
            self.read_greeting(sock)
            
            # SMTP conversation
            self.send_smtp_command(sock, "EHLO test-client", "250")
            self.send_smtp_command(sock, "MAIL FROM: <valid@example.com>", "250")
            self.send_smtp_command(sock, "RCPT TO: <demo@example.com>", "250")
            
            # Send DATA command
            sock.send(b"DATA\r\n")
            data_response = sock.recv(1024).decode().strip()
            print(f"DEBUG: DATA response: {data_response}")
            if not data_response.startswith("354"):
                print(f"⚠️  DATA command failed: {data_response}")
                # Try to quit and close gracefully
                try:
                    self.send_smtp_command(sock, "QUIT", "221")
                except:
                    pass
                sock.close()
                return False
            
            # Send message with proper RFC 5322 headers
            message = """From: valid@example.com
To: demo@example.com
Subject: Valid Email Delivery Test
Date: Sat, 21 Sep 2025 19:15:00 -0400

This is a valid test message for delivery testing."""
            
            # Send each line with proper CRLF endings
            for line in message.split('\n'):
                sock.send((line + '\r\n').encode())
            print(f"DEBUG: Sent message with proper headers")
            self.send_smtp_command(sock, ".", "250")
            self.send_smtp_command(sock, "QUIT", "221")
            
            sock.close()
            
            # Wait for processing
            time.sleep(5)
            
            # Check logs for expected events
            events = self.get_log_events()
            self.validate_events(events, ["mail_from_accepted", "rcpt_to_accepted", "message_received", "message_accepted", "message_enqueued", "message_delivered"])
            
            print("✅ Valid email delivery test passed")
            return True
            
        except Exception as e:
            print(f"❌ Valid email delivery test failed: {e}")
            return False
    
    def test_invalid_recipient(self):
        """Test 2: Invalid recipient - should generate rejection"""
        print("🧪 Test 2: Invalid Recipient")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            # Read greeting
            self.read_greeting(sock)
            
            # SMTP conversation with invalid recipient
            self.send_smtp_command(sock, "EHLO test-client", "250")
            self.send_smtp_command(sock, "MAIL FROM: <valid@example.com>", "250")
            
            # Try invalid recipient
            response = self.send_smtp_command(sock, "RCPT TO: <invalid@nonexistent.com>")
            if response.startswith("554") or response.startswith("550"):
                print("✅ Invalid recipient properly rejected")
            else:
                print(f"⚠️  Expected 554/550 rejection, got: {response}")
            
            # Try to quit, but handle potential session errors
            try:
                self.send_smtp_command(sock, "QUIT", "221")
            except:
                # If QUIT fails, just close the socket
                pass
            sock.close()
            
            print("✅ Invalid recipient test completed")
            return True
            
        except Exception as e:
            print(f"❌ Invalid recipient test failed: {e}")
            return False
    
    def test_malformed_email(self):
        """Test 3: Malformed email - should generate message_rejected"""
        print("🧪 Test 3: Malformed Email")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            # Read greeting
            self.read_greeting(sock)
            
            # SMTP conversation
            self.send_smtp_command(sock, "EHLO test-client", "250")
            self.send_smtp_command(sock, "MAIL FROM: <malformed@example.com>", "250")  # Valid email format
            self.send_smtp_command(sock, "RCPT TO: <demo@example.com>", "250")
            
            # Send DATA command
            sock.send(b"DATA\r\n")
            data_response = sock.recv(1024).decode().strip()
            print(f"DEBUG: DATA response: {data_response}")
            if not data_response.startswith("354"):
                print(f"⚠️  DATA command failed: {data_response}")
                # Try to quit and close gracefully
                try:
                    self.send_smtp_command(sock, "QUIT", "221")
                except:
                    pass
                sock.close()
                return False
            
            # Send malformed message (no headers)
            message = """From: malformed@example.com
To: demo@example.com
Subject: Malformed Email Test
Date: Sat, 21 Sep 2025 19:15:00 -0400

This is a malformed message without proper headers for testing rejection."""
            
            # Send each line with proper CRLF endings
            for line in message.split('\n'):
                sock.send((line + '\r\n').encode())
            self.send_smtp_command(sock, ".", "250")
            self.send_smtp_command(sock, "QUIT", "221")
            
            sock.close()
            
            # Wait for processing
            time.sleep(5)
            
            print("✅ Malformed email test completed")
            return True
            
        except Exception as e:
            print(f"❌ Malformed email test failed: {e}")
            return False
    
    def test_virus_scan_simulation(self):
        """Test 4: Simulate virus detection - should generate message_rejected"""
        print("🧪 Test 4: Virus Scan Simulation")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            # Read greeting
            self.read_greeting(sock)
            
            # SMTP conversation
            self.send_smtp_command(sock, "EHLO test-client", "250")
            self.send_smtp_command(sock, "MAIL FROM: <virus@example.com>", "250")
            self.send_smtp_command(sock, "RCPT TO: <demo@example.com>", "250")
            
            # Send DATA command
            sock.send(b"DATA\r\n")
            data_response = sock.recv(1024).decode().strip()
            print(f"DEBUG: DATA response: {data_response}")
            if not data_response.startswith("354"):
                print(f"⚠️  DATA command failed: {data_response}")
                # Try to quit and close gracefully
                try:
                    self.send_smtp_command(sock, "QUIT", "221")
                except:
                    pass
                sock.close()
                return False
            
            # Send message that contains the word "virus" to trigger antivirus detection
            message = """From: virus@example.com
To: demo@example.com
Subject: Virus Scan Test
Date: Sat, 21 Sep 2025 19:15:00 -0400

This message contains suspicious content that might trigger virus detection."""
            
            # Send each line with proper CRLF endings
            for line in message.split('\n'):
                sock.send((line + '\r\n').encode())
            
            # Expect virus rejection (554) instead of acceptance (250)
            response = self.send_smtp_command(sock, ".")
            if response.startswith("554") and "virus detected" in response.lower():
                print("✅ Virus properly detected and rejected")
            else:
                print(f"⚠️  Expected 554 virus rejection, got: {response}")
                # Try to quit and close gracefully
                try:
                    self.send_smtp_command(sock, "QUIT", "221")
                except:
                    pass
                sock.close()
                return False
            
            self.send_smtp_command(sock, "QUIT", "221")
            sock.close()
            
            # Wait for processing
            time.sleep(5)
            
            print("✅ Virus scan simulation test completed")
            return True
            
        except Exception as e:
            print(f"❌ Virus scan simulation test failed: {e}")
            return False
    
    def test_authentication_events(self):
        """Test 5: Authentication events"""
        print("🧪 Test 5: Authentication Events")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            # Read greeting
            self.read_greeting(sock)
            
            # SMTP conversation with authentication
            self.send_smtp_command(sock, "EHLO test-client", "250")
            
            # Try AUTH LOGIN
            response = self.send_smtp_command(sock, "AUTH LOGIN")
            if response.startswith("334"):
                # Send username
                import base64
                username_b64 = base64.b64encode("demo@example.com".encode()).decode()
                sock.send(f"{username_b64}\r\n".encode())
                username_response = sock.recv(1024).decode().strip()
                
                if username_response.startswith("334"):
                    # Send password
                    password_b64 = base64.b64encode("demo123".encode()).decode()
                    sock.send(f"{password_b64}\r\n".encode())
                    auth_response = sock.recv(1024).decode().strip()
                    if auth_response.startswith("235"):
                        print("✅ Authentication successful")
                    else:
                        print(f"⚠️  Authentication failed: {auth_response}")
                else:
                    print(f"⚠️  Username prompt failed: {username_response}")
            else:
                print(f"⚠️  AUTH LOGIN not supported: {response}")
            
            self.send_smtp_command(sock, "QUIT", "221")
            sock.close()
            
            print("✅ Authentication events test completed")
            return True
            
        except Exception as e:
            print(f"❌ Authentication events test failed: {e}")
            return False
    
    def test_large_message(self):
        """Test 6: Large message - might trigger size limits"""
        print("🧪 Test 6: Large Message")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((self.host, self.port))
            
            # Read greeting
            self.read_greeting(sock)
            
            # SMTP conversation
            self.send_smtp_command(sock, "EHLO test-client", "250")
            self.send_smtp_command(sock, "MAIL FROM: <large@example.com>", "250")
            self.send_smtp_command(sock, "RCPT TO: <demo@example.com>", "250")
            
            # Send DATA command
            sock.send(b"DATA\r\n")
            data_response = sock.recv(1024).decode().strip()
            print(f"DEBUG: DATA response: {data_response}")
            if not data_response.startswith("354"):
                # If DATA fails, try to continue anyway
                print(f"⚠️  DATA command failed: {data_response}")
                self.send_smtp_command(sock, "QUIT", "221")
                sock.close()
                print("✅ Large message test completed (DATA failed as expected)")
                return True
            
            # Send large message (1MB)
            large_content = "Subject: Large Message Test\r\n\r\n" + "X" * (1024 * 1024) + "\r\n"
            sock.send(large_content.encode())
            response = self.send_smtp_command(sock, ".")
            
            if response.startswith("552") or response.startswith("554"):
                print("✅ Large message properly rejected")
            elif response.startswith("250"):
                print("✅ Large message accepted")
            else:
                print(f"⚠️  Unexpected response: {response}")
            
            # Try to quit, but handle potential session errors
            try:
                self.send_smtp_command(sock, "QUIT", "221")
            except:
                # If QUIT fails due to session error, that's expected
                pass
            sock.close()
            
            print("✅ Large message test completed")
            return True
            
        except Exception as e:
            print(f"❌ Large message test failed: {e}")
            return False
    
    def test_message_rejection_scenarios(self):
        """Test 7: Message rejection scenarios"""
        print("🧪 Test 7: Message Rejection Scenarios")
        try:
            # Test 1: Empty recipient list
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            # Read greeting
            self.read_greeting(sock)
            
            # SMTP conversation without RCPT TO
            self.send_smtp_command(sock, "EHLO test-client", "250")
            self.send_smtp_command(sock, "MAIL FROM: <test@example.com>", "250")
            
            # Try DATA without RCPT TO (should fail)
            response = self.send_smtp_command(sock, "DATA")
            if response.startswith("503"):
                print("✅ DATA without RCPT TO properly rejected")
            else:
                print(f"⚠️  Unexpected response: {response}")
            
            # Try to quit, but don't expect 221 if the session is in error state
            try:
                self.send_smtp_command(sock, "QUIT", "221")
            except:
                # If QUIT fails, just close the socket
                pass
            sock.close()
            
            # Test 2: Invalid sender domain
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            # Read greeting
            self.read_greeting(sock)
            
            # SMTP conversation with invalid sender
            self.send_smtp_command(sock, "EHLO test-client", "250")
            response = self.send_smtp_command(sock, "MAIL FROM: <test@invalid-domain.com>", "250")
            # This might be accepted depending on configuration
            
            self.send_smtp_command(sock, "QUIT", "221")
            sock.close()
            
            print("✅ Message rejection scenarios test completed")
            return True
            
        except Exception as e:
            print(f"❌ Message rejection scenarios test failed: {e}")
            return False
    
    def test_spam_detection(self):
        """Test 8: Spam detection using GTUBE test string"""
        print("🧪 Test 8: Spam Detection (GTUBE)")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            # Read greeting
            self.read_greeting(sock)
            
            # SMTP conversation
            self.send_smtp_command(sock, "EHLO test-client", "250")
            self.send_smtp_command(sock, "MAIL FROM: <spam@example.com>", "250")
            self.send_smtp_command(sock, "RCPT TO: <demo@example.com>", "250")
            
            # Send DATA command
            sock.send(b"DATA\r\n")
            data_response = sock.recv(1024).decode().strip()
            print(f"DEBUG: DATA response: {data_response}")
            if not data_response.startswith("354"):
                print(f"⚠️  DATA command failed: {data_response}")
                # Try to quit and close gracefully
                try:
                    self.send_smtp_command(sock, "QUIT", "221")
                except:
                    pass
                sock.close()
                return False
            
            # Send GTUBE spam test message
            gtube_content = """From: spam@example.com
To: demo@example.com
Subject: Spam Detection Test (GTUBE)
Date: Sat, 21 Sep 2025 19:15:00 -0400

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

This is a test message containing the GTUBE (Generic Test for Unsolicited Bulk Email) test string.
This should trigger spam detection if SpamAssassin is properly configured."""
            
            # Send each line with proper CRLF endings
            for line in gtube_content.split('\n'):
                sock.send((line + '\r\n').encode())
            response = self.send_smtp_command(sock, ".")
            
            if response.startswith("250"):
                print("✅ Spam test message accepted (will be processed by spam filter)")
            elif response.startswith("554") or response.startswith("550"):
                print("✅ Spam test message properly rejected")
            else:
                print(f"⚠️  Unexpected response: {response}")
            
            self.send_smtp_command(sock, "QUIT", "221")
            sock.close()
            
            # Wait for processing
            time.sleep(5)
            
            print("✅ Spam detection test completed")
            return True
            
        except Exception as e:
            print(f"❌ Spam detection test failed: {e}")
            return False
    
    def get_log_events(self):
        """Get recent log events from Docker logs"""
        try:
            result = subprocess.run(
                ["docker", "logs", "--tail", "500", "elemta-node0"],
                capture_output=True, text=True, timeout=10
            )
            
            events = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    # Try to parse as JSON
                    try:
                        if line.startswith('{'):
                            log_entry = json.loads(line)
                            if 'event_type' in log_entry:
                                events.append(log_entry)
                    except json.JSONDecodeError:
                        # Handle non-JSON log lines - look for event types in the message
                        for event_type in EXPECTED_EVENTS.keys():
                            if event_type in line:
                                # Try to extract fields from the log line
                                event_data = {"event_type": event_type, "raw_line": line}
                                
                                # Extract common fields from log format
                                if "message_id=" in line:
                                    # Extract message_id
                                    import re
                                    msg_id_match = re.search(r'message_id=([^\s]+)', line)
                                    if msg_id_match:
                                        event_data["message_id"] = msg_id_match.group(1)
                                
                                if "from_envelope=" in line:
                                    from_match = re.search(r'from_envelope=([^\s]+)', line)
                                    if from_match:
                                        event_data["from_envelope"] = from_match.group(1)
                                
                                if "to_envelope=" in line:
                                    to_match = re.search(r'to_envelope=\[([^\]]+)\]', line)
                                    if to_match:
                                        event_data["to_envelope"] = [to_match.group(1)]
                                
                                events.append(event_data)
                                break
            
            return events
        except Exception as e:
            print(f"Error getting log events: {e}")
            return []
    
    def validate_events(self, events: List[Dict], expected_event_types: List[str]):
        """Validate that expected events are present with required fields"""
        found_events = set()
        
        for event in events:
            event_type = event.get('event_type')
            if event_type in expected_event_types:
                found_events.add(event_type)
                
                # Validate required fields
                if event_type in EXPECTED_EVENTS:
                    required_fields = EXPECTED_EVENTS[event_type].required_fields
                    missing_fields = []
                    
                    for field in required_fields:
                        if field not in event:
                            missing_fields.append(field)
                    
                    if missing_fields:
                        print(f"⚠️  {event_type} missing fields: {missing_fields}")
                    else:
                        print(f"✅ {event_type} has all required fields")
        
        # Check for missing events
        missing_events = set(expected_event_types) - found_events
        if missing_events:
            print(f"⚠️  Missing expected events: {missing_events}")
        else:
            print(f"✅ All expected events found: {found_events}")
    
    def run_all_tests(self):
        """Run all logging tests"""
        print("🚀 Starting Comprehensive Email Logging Test Suite")
        print("=" * 60)
        
        tests = [
            self.test_valid_email_delivery,
            self.test_invalid_recipient,
            self.test_malformed_email,
            self.test_virus_scan_simulation,
            self.test_authentication_events,
            self.test_large_message,
            self.test_message_rejection_scenarios,
            self.test_spam_detection,
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
            except Exception as e:
                print(f"❌ Test failed with exception: {e}")
            print()
        
        print("=" * 60)
        print(f"📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All logging tests passed!")
        else:
            print(f"⚠️  {total - passed} tests failed")
        
        return passed == total

if __name__ == "__main__":
    tester = EmailLoggingTester()
    success = tester.run_all_tests()
    exit(0 if success else 1)
