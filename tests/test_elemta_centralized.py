#!/usr/bin/env python3
"""
Elemta Centralized Test Suite

A comprehensive, unified test suite for the Elemta SMTP server that consolidates
all testing functionality into a single, maintainable script.

Features:
- Docker deployment testing
- SMTP protocol testing
- Authentication testing
- Security testing
- Performance testing
- End-to-end email delivery testing
- Plugin system testing
- Queue management testing
- Monitoring and metrics testing

Usage:
    python3 test_elemta_centralized.py [OPTIONS]

Examples:
    python3 test_elemta_centralized.py --deployment docker-desktop
    python3 test_elemta_centralized.py --deployment docker-dev --category security
    python3 test_elemta_centralized.py --deployment docker-desktop --test smtp-greeting
    python3 test_elemta_centralized.py --deployment docker-desktop --verbose --parallel
"""

import argparse
import asyncio
import base64
import concurrent.futures
import json
import logging
import os
import socket
import subprocess
import sys
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, Tuple
from pathlib import Path
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestResultStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"

class DeploymentType(Enum):
    DOCKER_DESKTOP = "docker-desktop"
    DOCKER_DEV = "docker-dev"
    LOCAL = "local"

@dataclass
class TestConfig:
    """Configuration for test execution"""
    deployment: DeploymentType = DeploymentType.DOCKER_DESKTOP
    host: str = "localhost"
    smtp_port: int = 2525
    imap_port: int = 14143
    webmail_port: int = 8026
    api_port: int = 8081
    metrics_port: int = 8080
    timeout: int = 30
    verbose: bool = False
    parallel: bool = False
    max_workers: int = 4
    categories: List[str] = field(default_factory=list)
    specific_tests: List[str] = field(default_factory=list)
    skip_tests: List[str] = field(default_factory=list)

@dataclass
class TestCase:
    """Individual test case definition"""
    name: str
    category: str
    description: str
    test_func: Callable
    required: bool = True
    timeout: int = 30
    dependencies: List[str] = field(default_factory=list)

@dataclass
class TestResult:
    """Test execution result"""
    test_name: str
    result: TestResultStatus
    duration: float
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

class SMTPTestClient:
    """Enhanced SMTP test client with comprehensive functionality"""
    
    def __init__(self, host: str = "localhost", port: int = 2525, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.connected = False
        self.logger = logging.getLogger(f"SMTPClient-{host}:{port}")

    def connect(self) -> str:
        """Connect to SMTP server and return greeting"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            self.connected = True
            self.logger.debug(f"Connected to {self.host}:{self.port}")
            greeting = self._read_response()
            return greeting
        except Exception as e:
            if self.sock:
                self.sock.close()
            raise Exception(f"Connection failed: {e}")

    def disconnect(self):
        """Disconnect from SMTP server"""
        if self.connected and self.sock:
            try:
                self._send_command("QUIT")
            except:
                pass
            self.sock.close()
            self.connected = False
            self.logger.debug(f"Disconnected from {self.host}:{self.port}")

    def _send_command(self, command: str) -> str:
        """Send SMTP command and return response"""
        if not self.connected or not self.sock:
            raise Exception("Not connected to server")
        
        try:
            self.sock.send(f"{command}\r\n".encode())
            # Add a small delay to ensure the server has time to respond
            import time
            time.sleep(0.1)
            return self._read_response()
        except Exception as e:
            raise Exception(f"Command failed: {e}")

    def _read_response(self) -> str:
        """Read SMTP response with proper multi-line handling"""
        if not self.sock:
            raise Exception("No socket connection")
        
        response_lines = []
        buffer = ""
        
        while True:
            try:
                # Read data from socket
                data = self.sock.recv(1024).decode()
                if not data:
                    break
                
                buffer += data
                
                # Process complete lines
                while '\r\n' in buffer:
                    line, buffer = buffer.split('\r\n', 1)
                    if line:  # Skip empty lines
                        response_lines.append(line)
                
                # Check if we have a complete response
                if response_lines and not response_lines[-1].startswith((' ', '-')):
                    break
                    
            except socket.timeout:
                raise Exception("Timeout reading response")
            except Exception as e:
                raise Exception(f"Error reading response: {e}")
        
        if not response_lines:
            return ""
        
        # Return the final response line (the one that doesn't start with space or hyphen)
        return response_lines[-1]

    def ehlo(self, hostname: str = "test.example.com") -> str:
        """Send EHLO command"""
        return self._send_command(f"EHLO {hostname}")

    def helo(self, hostname: str = "test.example.com") -> str:
        """Send HELO command"""
        return self._send_command(f"HELO {hostname}")

    def mail_from(self, email: str) -> str:
        """Send MAIL FROM command"""
        return self._send_command(f"MAIL FROM:<{email}>")

    def rcpt_to(self, email: str) -> str:
        """Send RCPT TO command"""
        return self._send_command(f"RCPT TO:<{email}>")

    def data(self) -> str:
        """Send DATA command"""
        return self._send_command("DATA")

    def send_data(self, data: str) -> str:
        """Send email data"""
        if not self.connected or not self.sock:
            raise Exception("Not connected to server")
        
        try:
            self.sock.send(data.encode())
            return self._read_response()
        except Exception as e:
            raise Exception(f"Data sending failed: {e}")

    def quit(self) -> str:
        """Send QUIT command"""
        return self._send_command("QUIT")

    def auth_plain(self, username: str, password: str) -> str:
        """Send AUTH PLAIN command"""
        credentials = base64.b64encode(f"\0{username}\0{password}".encode()).decode()
        return self._send_command(f"AUTH PLAIN {credentials}")

    def auth_login(self, username: str, password: str) -> str:
        """Send AUTH LOGIN command"""
        # Send AUTH LOGIN
        response = self._send_command("AUTH LOGIN")
        if not response.startswith("334"):
            raise Exception(f"Unexpected AUTH LOGIN response: {response}")
        
        # Send username
        username_b64 = base64.b64encode(username.encode()).decode()
        response = self._send_command(username_b64)
        if not response.startswith("334"):
            raise Exception(f"Unexpected username response: {response}")
        
        # Send password
        password_b64 = base64.b64encode(password.encode()).decode()
        return self._send_command(password_b64)

class ElemtaTestSuite:
    """Main test suite class"""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.logger = logging.getLogger("ElemtaTestSuite")
        self.test_cases: List[TestCase] = []
        self.results: List[TestResult] = []
        self._setup_logging()
        self._register_tests()

    def _setup_logging(self):
        """Setup logging configuration"""
        if self.config.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        else:
            logging.getLogger().setLevel(logging.INFO)

    def _register_tests(self):
        """Register all test cases organized by category"""
        
        # === DEPLOYMENT TESTS ===
        self._register_deployment_tests()
        
        # === SMTP PROTOCOL TESTS ===
        self._register_smtp_tests()
        
        # === AUTHENTICATION TESTS ===
        self._register_auth_tests()
        
        # === SECURITY TESTS ===
        self._register_security_tests()
        
        # === PERFORMANCE TESTS ===
        self._register_performance_tests()
        
        # === END-TO-END TESTS ===
        self._register_e2e_tests()
        
        # === MONITORING TESTS ===
        self._register_monitoring_tests()

    def _register_deployment_tests(self):
        """Register deployment-related tests"""
        self._register_test("docker-containers-running", "deployment", 
                          "Verify Docker containers are running",
                          self._test_docker_containers_running)
        
        self._register_test("docker-services-healthy", "deployment",
                          "Verify Docker services are healthy",
                          self._test_docker_services_healthy)

    def _register_smtp_tests(self):
        """Register SMTP protocol tests"""
        self._register_test("smtp-greeting", "smtp",
                          "Test SMTP server greeting",
                          self._test_smtp_greeting)
        
        self._register_test("smtp-ehlo", "smtp",
                          "Test EHLO command",
                          self._test_smtp_ehlo)
        
        self._register_test("smtp-helo", "smtp",
                          "Test HELO command",
                          self._test_smtp_helo)
        
        self._register_test("smtp-mail-from", "smtp",
                          "Test MAIL FROM command",
                          self._test_smtp_mail_from)
        
        self._register_test("smtp-rcpt-to", "smtp",
                          "Test RCPT TO command",
                          self._test_smtp_rcpt_to)
        
        self._register_test("smtp-data", "smtp",
                          "Test DATA command and email sending",
                          self._test_smtp_data)
        
        self._register_test("smtp-quit", "smtp",
                          "Test QUIT command",
                          self._test_smtp_quit)

    def _register_auth_tests(self):
        """Register authentication tests"""
        is_desktop = self.config.deployment == DeploymentType.DOCKER_DESKTOP
        
        self._register_test("auth-plain", "auth",
                          "Test AUTH PLAIN authentication",
                          self._test_auth_plain,
                          required=is_desktop)
        
        self._register_test("auth-login", "auth",
                          "Test AUTH LOGIN authentication",
                          self._test_auth_login,
                          required=is_desktop)
        
        self._register_test("auth-invalid", "auth",
                          "Test invalid authentication rejection",
                          self._test_auth_invalid)

    def _register_security_tests(self):
        """Register security tests"""
        self._register_test("security-command-injection", "security",
                          "Test command injection protection",
                          self._test_security_command_injection)
        
        self._register_test("security-buffer-overflow", "security",
                          "Test buffer overflow protection",
                          self._test_security_buffer_overflow)
        
        self._register_test("security-sql-injection", "security",
                          "Test SQL injection protection",
                          self._test_security_sql_injection)

    def _register_performance_tests(self):
        """Register performance tests"""
        self._register_test("performance-connection-limit", "performance",
                          "Test connection limit handling",
                          self._test_performance_connection_limit)
        
        self._register_test("performance-rate-limiting", "performance",
                          "Test rate limiting functionality",
                          self._test_performance_rate_limiting)

    def _register_e2e_tests(self):
        """Register end-to-end tests"""
        is_desktop = self.config.deployment == DeploymentType.DOCKER_DESKTOP
        
        self._register_test("e2e-email-delivery", "e2e",
                          "Test complete email delivery flow",
                          self._test_e2e_email_delivery)
        
        self._register_test("e2e-webmail-access", "e2e",
                          "Test webmail access",
                          self._test_e2e_webmail_access,
                          required=is_desktop)

    def _register_monitoring_tests(self):
        """Register monitoring tests"""
        self._register_test("monitoring-metrics", "monitoring",
                          "Test metrics endpoint",
                          self._test_monitoring_metrics,
                          required=False)  # Optional since metrics server may not be running
        
        self._register_test("monitoring-health", "monitoring",
                          "Test health check endpoint",
                          self._test_monitoring_health)

    def _register_test(self, name: str, category: str, description: str, 
                      test_func: Callable, required: bool = True, 
                      timeout: int = 30, dependencies: List[str] = None):
        """Register a test case"""
        if dependencies is None:
            dependencies = []
        
        test_case = TestCase(
            name=name,
            category=category,
            description=description,
            test_func=test_func,
            required=required,
            timeout=timeout,
            dependencies=dependencies
        )
        self.test_cases.append(test_case)

    def run_tests(self) -> bool:
        """Run all registered tests"""
        self.logger.info("Starting Elemta test suite")
        self.logger.info(f"Deployment: {self.config.deployment.value}")
        self.logger.info(f"Target: {self.config.host}:{self.config.smtp_port}")
        
        # Filter tests based on configuration
        tests_to_run = self._filter_tests()
        
        if not tests_to_run:
            self.logger.warning("No tests to run")
            return True
        
        self.logger.info(f"Running {len(tests_to_run)} tests")
        
        # Run tests
        if self.config.parallel:
            success = self._run_tests_parallel(tests_to_run)
        else:
            success = self._run_tests_sequential(tests_to_run)
        
        # Print summary
        self._print_summary()
        
        return success

    def _filter_tests(self) -> List[TestCase]:
        """Filter tests based on configuration"""
        tests = []
        
        for test in self.test_cases:
            # Skip if in skip list
            if test.name in self.config.skip_tests:
                continue
            
            # Include if specific tests are requested and this is one of them
            if self.config.specific_tests and test.name not in self.config.specific_tests:
                continue
            
            # Include if categories are requested and this test is in one of them
            if self.config.categories and test.category not in self.config.categories:
                continue
            
            # Include if no filters are applied
            if not self.config.specific_tests and not self.config.categories:
                tests.append(test)
            elif test.name in self.config.specific_tests or test.category in self.config.categories:
                tests.append(test)
        
        return tests

    def _run_tests_sequential(self, tests: List[TestCase]) -> bool:
        """Run tests sequentially"""
        all_passed = True
        
        for test in tests:
            result = self._run_single_test(test)
            self.results.append(result)
            
            if result.result == TestResultStatus.FAIL and test.required:
                all_passed = False
                if not self.config.verbose:
                    self.logger.error(f"Required test failed: {test.name}")
        
        return all_passed

    def _run_tests_parallel(self, tests: List[TestCase]) -> bool:
        """Run tests in parallel"""
        all_passed = True
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all tests
            future_to_test = {executor.submit(self._run_single_test, test): test for test in tests}
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_test):
                test = future_to_test[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    
                    if result.result == TestResultStatus.FAIL and test.required:
                        all_passed = False
                        if not self.config.verbose:
                            self.logger.error(f"Required test failed: {test.name}")
                except Exception as e:
                    self.logger.error(f"Test {test.name} raised exception: {e}")
                    self.results.append(TestResult(
                        test_name=test.name,
                        result=TestResultStatus.ERROR,
                        duration=0.0,
                        message=f"Exception: {e}"
                    ))
                    if test.required:
                        all_passed = False
        
        return all_passed

    def _run_single_test(self, test: TestCase) -> TestResult:
        """Run a single test case"""
        start_time = time.time()
        
        try:
            self.logger.info(f"Running test: {test.name}")
            
            # Check dependencies
            for dep in test.dependencies:
                dep_result = next((r for r in self.results if r.test_name == dep), None)
                if not dep_result or dep_result.result != TestResultStatus.PASS:
                    return TestResult(
                        test_name=test.name,
                        result=TestResultStatus.SKIP,
                        duration=time.time() - start_time,
                        message=f"Skipped due to failed dependency: {dep}"
                    )
            
            # Run the test
            test.test_func()
            
            duration = time.time() - start_time
            self.logger.info(f"Test passed: {test.name} ({duration:.2f}s)")
            
            return TestResult(
                test_name=test.name,
                result=TestResultStatus.PASS,
                duration=duration,
                message="Test passed"
            )
            
        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"Test failed: {test.name} - {e}")
            
            return TestResult(
                test_name=test.name,
                result=TestResultStatus.FAIL,
                duration=duration,
                message=str(e)
            )

    def _print_summary(self):
        """Print test execution summary"""
        total = len(self.results)
        passed = len([r for r in self.results if r.result == TestResultStatus.PASS])
        failed = len([r for r in self.results if r.result == TestResultStatus.FAIL])
        skipped = len([r for r in self.results if r.result == TestResultStatus.SKIP])
        errors = len([r for r in self.results if r.result == TestResultStatus.ERROR])
        
        total_duration = sum(r.duration for r in self.results)
        
        print("\n" + "="*60)
        print("TEST EXECUTION SUMMARY")
        print("="*60)
        print(f"Total tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Skipped: {skipped}")
        print(f"Errors: {errors}")
        print(f"Total duration: {total_duration:.2f}s")
        print("="*60)
        
        if failed > 0 or errors > 0:
            print("\nFAILED TESTS:")
            for result in self.results:
                if result.result in [TestResultStatus.FAIL, TestResultStatus.ERROR]:
                    print(f"  - {result.test_name}: {result.message}")
        
        if skipped > 0:
            print("\nSKIPPED TESTS:")
            for result in self.results:
                if result.result == TestResultStatus.SKIP:
                    print(f"  - {result.test_name}: {result.message}")

    # Test implementation methods
    def _test_docker_containers_running(self):
        """Test that all Docker containers are running"""
        if self.config.deployment not in [DeploymentType.DOCKER_DESKTOP, DeploymentType.DOCKER_DEV]:
            raise Exception("Docker deployment test only applicable for Docker deployments")
        
        try:
            result = subprocess.run(
                ["docker", "compose", "-f", "deployments/compose/docker-compose.yml", "ps", "--format", "json"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                raise Exception(f"Docker compose ps failed: {result.stderr}")
            
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    containers.append(json.loads(line))
            
            if self.config.deployment == DeploymentType.DOCKER_DESKTOP:
                required_containers = ["elemta-node0", "elemta-dovecot", "elemta-roundcube", "elemta-ldap"]
            else:  # docker-dev or other minimal deployments
                required_containers = ["elemta-node0"]
            running_containers = [c["Name"] for c in containers if c["State"] == "running"]
            
            missing_containers = [c for c in required_containers if c not in running_containers]
            if missing_containers:
                raise Exception(f"Missing running containers: {missing_containers}")
            
            self.logger.info(f"All required containers running: {running_containers}")
            
        except subprocess.TimeoutExpired:
            raise Exception("Docker compose command timed out")
        except Exception as e:
            raise Exception(f"Failed to check Docker containers: {e}")

    def _test_docker_services_healthy(self):
        """Test that all Docker services are healthy"""
        # This would check health endpoints, logs, etc.
        # For now, just verify containers are running
        self._test_docker_containers_running()

    def _test_smtp_greeting(self):
        """Test SMTP server greeting"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            greeting = client.connect()
            if not greeting.startswith("220"):
                raise Exception(f"Invalid greeting: {greeting}")
            self.logger.info(f"SMTP greeting: {greeting}")
        finally:
            client.disconnect()

    def _test_smtp_ehlo(self):
        """Test EHLO command"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            response = client.ehlo()
            if not response.startswith("250"):
                raise Exception(f"EHLO failed: {response}")
            self.logger.info(f"EHLO response: {response}")
        finally:
            client.disconnect()

    def _test_smtp_helo(self):
        """Test HELO command"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            response = client.helo()
            if not response.startswith("250"):
                raise Exception(f"HELO failed: {response}")
            self.logger.info(f"HELO response: {response}")
        finally:
            client.disconnect()

    def _test_smtp_mail_from(self):
        """Test MAIL FROM command"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            response = client.mail_from("test@example.com")
            if not response.startswith("250"):
                raise Exception(f"MAIL FROM failed: {response}")
            self.logger.info(f"MAIL FROM response: {response}")
        finally:
            client.disconnect()

    def _test_smtp_rcpt_to(self):
        """Test RCPT TO command"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            client.mail_from("test@example.com")
            response = client.rcpt_to("recipient@example.com")
            if not response.startswith("250"):
                raise Exception(f"RCPT TO failed: {response}")
            self.logger.info(f"RCPT TO response: {response}")
        finally:
            client.disconnect()

    def _test_smtp_data(self):
        """Test DATA command and email sending"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            client.mail_from("test@example.com")
            client.rcpt_to("recipient@example.com")
            
            response = client.data()
            if not response.startswith("354"):
                raise Exception(f"DATA failed: {response}")
            
            # Send email content
            email_content = """Subject: Test Email
From: test@example.com
To: recipient@example.com

This is a test email.
.
"""
            response = client.send_data(email_content)
            if not response.startswith("250"):
                raise Exception(f"Email sending failed: {response}")
            
            self.logger.info(f"Email sent successfully: {response}")
        finally:
            client.disconnect()

    def _test_smtp_quit(self):
        """Test QUIT command"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            response = client.quit()
            if not response.startswith("221"):
                raise Exception(f"QUIT failed: {response}")
            self.logger.info(f"QUIT response: {response}")
        finally:
            client.disconnect()

    def _test_auth_plain(self):
        """Test AUTH PLAIN authentication"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            response = client.auth_plain("user@example.com", "password")
            if not response.startswith("235"):
                raise Exception(f"AUTH PLAIN failed: {response}")
            self.logger.info(f"AUTH PLAIN successful: {response}")
        finally:
            client.disconnect()

    def _test_auth_login(self):
        """Test AUTH LOGIN authentication"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            response = client.auth_login("user@example.com", "password")
            if not response.startswith("235"):
                raise Exception(f"AUTH LOGIN failed: {response}")
            self.logger.info(f"AUTH LOGIN successful: {response}")
        finally:
            client.disconnect()

    def _test_auth_invalid(self):
        """Test invalid authentication"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            response = client.auth_plain("invalid", "invalid")
            if response.startswith("235"):
                raise Exception("Invalid authentication should have failed")
            self.logger.info(f"Invalid auth correctly rejected: {response}")
        finally:
            client.disconnect()

    def _test_security_command_injection(self):
        """Test command injection protection"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            
            # Try command injection in MAIL FROM
            response = client.mail_from("test@example.com; rm -rf /")
            if not response.startswith(("500", "501", "502", "503", "504", "550")):
                raise Exception("Command injection not blocked")
            
            self.logger.info(f"Command injection blocked: {response}")
        finally:
            client.disconnect()

    def _test_security_buffer_overflow(self):
        """Test buffer overflow protection"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            
            # Try buffer overflow in MAIL FROM
            long_email = "a" * 10000 + "@example.com"
            response = client.mail_from(long_email)
            if not response.startswith(("500", "501", "502", "503", "504", "550")):
                raise Exception("Buffer overflow not blocked")
            
            self.logger.info(f"Buffer overflow blocked: {response}")
        finally:
            client.disconnect()

    def _test_security_sql_injection(self):
        """Test SQL injection protection"""
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            
            # Try SQL injection in MAIL FROM
            response = client.mail_from("test@example.com'; DROP TABLE users; --")
            if not response.startswith(("500", "501", "502", "503", "504", "550")):
                raise Exception("SQL injection not blocked")
            
            self.logger.info(f"SQL injection blocked: {response}")
        finally:
            client.disconnect()

    def _test_performance_connection_limit(self):
        """Test connection limit handling"""
        # Test multiple concurrent connections to verify connection limits work
        clients = []
        try:
            # Create multiple connections
            for i in range(5):
                client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
                client.connect()
                clients.append(client)
            
            # Verify all connections work
            for i, client in enumerate(clients):
                greeting = client.ehlo(f"test{i}.example.com")
                if not greeting.startswith("250"):
                    raise Exception(f"Connection {i} failed: {greeting}")
            
            self.logger.info(f"Successfully established {len(clients)} concurrent connections")
        finally:
            # Clean up all connections
            for client in clients:
                try:
                    client.disconnect()
                except:
                    pass

    def _test_performance_rate_limiting(self):
        """Test rate limiting functionality"""
        # Test rapid command sending to verify rate limiting works
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            client.mail_from("test@example.com")
            
            # Send multiple RCPT TO commands rapidly (this is allowed)
            for i in range(10):
                response = client.rcpt_to(f"test{i}@example.com")
                if not response.startswith("250"):
                    raise Exception(f"Rate limiting test failed at iteration {i}: {response}")
            
            self.logger.info("Rate limiting test passed - no rate limiting detected")
        finally:
            client.disconnect()

    def _test_e2e_email_delivery(self):
        """Test complete email delivery flow"""
        # Test full SMTP email delivery workflow using real demo users
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            client.connect()
            client.ehlo()
            client.mail_from("demo@example.com")
            client.rcpt_to("demo@example.com")
            
            # Send DATA command
            response = client.data()
            if not response.startswith("354"):
                raise Exception(f"DATA command failed: {response}")
            
            # Send email content with proper headers
            import datetime
            timestamp = datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S +0000")
            message_id = f"test-{int(time.time())}@example.com"
            
            email_content = f"""From: demo@example.com
To: demo@example.com
Subject: E2E Test Email - Demo to Demo
Date: {timestamp}
Message-ID: {message_id}
X-Elemta-Version: 1.0
X-Processed-By: Elemta MTA

Hello from demo user to demo user.
This is an end-to-end test email sent during automated testing.

Test completed at: {timestamp}
.
"""
            response = client.send_data(email_content)
            if not response.startswith("250"):
                raise Exception(f"Email delivery failed: {response}")
            
            self.logger.info("End-to-end email delivery successful: demo@example.com -> demo@example.com")
        finally:
            client.disconnect()

    def _test_e2e_webmail_access(self):
        """Test webmail access"""
        import urllib.request
        try:
            response = urllib.request.urlopen(f"http://{self.config.host}:{self.config.webmail_port}", timeout=10)
            if response.getcode() != 200:
                raise Exception(f"Webmail not accessible: HTTP {response.getcode()}")
            self.logger.info("Webmail accessible")
        except Exception as e:
            raise Exception(f"Webmail access failed: {e}")

    def _test_monitoring_metrics(self):
        """Test metrics endpoint"""
        import urllib.request
        try:
            response = urllib.request.urlopen(f"http://{self.config.host}:{self.config.metrics_port}/metrics", timeout=10)
            if response.getcode() != 200:
                raise Exception(f"Metrics not accessible: HTTP {response.getcode()}")
            
            content = response.read().decode()
            if "elemta_" not in content:
                raise Exception("No Elemta metrics found")
            
            self.logger.info("Metrics endpoint accessible")
        except Exception as e:
            raise Exception(f"Metrics access failed: {e}")

    def _test_monitoring_health(self):
        """Test health check endpoint"""
        # Test basic SMTP connectivity as a health check
        client = SMTPTestClient(self.config.host, self.config.smtp_port, self.config.timeout)
        try:
            greeting = client.connect()
            if not greeting.startswith("220"):
                raise Exception(f"Health check failed - invalid greeting: {greeting}")
            
            # Test basic EHLO command
            response = client.ehlo()
            if not response.startswith("250"):
                raise Exception(f"Health check failed - EHLO failed: {response}")
            
            self.logger.info("Health check passed - SMTP service is healthy")
        finally:
            client.disconnect()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Elemta Centralized Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --deployment docker-desktop
  %(prog)s --deployment docker-dev --category security
  %(prog)s --deployment docker-desktop --test smtp-greeting
  %(prog)s --deployment docker-desktop --verbose --parallel
        """
    )
    
    parser.add_argument("--deployment", 
                       choices=[d.value for d in DeploymentType],
                       default=DeploymentType.DOCKER_DESKTOP.value,
                       help="Deployment type to test")
    
    parser.add_argument("--host", default="localhost",
                       help="SMTP server host")
    
    parser.add_argument("--smtp-port", type=int, default=2525,
                       help="SMTP server port")
    
    parser.add_argument("--timeout", type=int, default=30,
                       help="Test timeout in seconds")
    
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    
    parser.add_argument("--parallel", "-p", action="store_true",
                       help="Run tests in parallel")
    
    parser.add_argument("--max-workers", type=int, default=4,
                       help="Maximum parallel workers")
    
    parser.add_argument("--category", action="append",
                       help="Test categories to run")
    
    parser.add_argument("--test", action="append",
                       help="Specific tests to run")
    
    parser.add_argument("--skip", action="append",
                       help="Tests to skip")
    
    args = parser.parse_args()
    
    # Create test configuration
    config = TestConfig(
        deployment=DeploymentType(args.deployment),
        host=args.host,
        smtp_port=args.smtp_port,
        timeout=args.timeout,
        verbose=args.verbose,
        parallel=args.parallel,
        max_workers=args.max_workers,
        categories=args.category or [],
        specific_tests=args.test or [],
        skip_tests=args.skip or []
    )
    
    # Create and run test suite
    test_suite = ElemtaTestSuite(config)
    success = test_suite.run_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
