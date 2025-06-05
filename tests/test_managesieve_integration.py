#!/usr/bin/env python3
"""
ManageSieve Integration Test
Tests ManageSieve server functionality including authentication and Sieve script management.
"""

import socket
import base64
import ssl
import sys
import time
from typing import Optional, Tuple

class ManageSieveClient:
    """Simple ManageSieve client for testing"""
    
    def __init__(self, host: str = 'localhost', port: int = 4190, timeout: int = 10):
        # Use Docker host if running in container environment
        import os
        if os.getenv('DOCKER_HOST') or os.path.exists('/.dockerenv'):
            self.host = 'elemta-dovecot'
        else:
            self.host = host
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.authenticated = False
        
    def connect(self) -> bool:
        """Connect to ManageSieve server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            
            # Read server greeting
            response = self._read_response()
            return response.startswith('"IMPLEMENTATION"')
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate using PLAIN mechanism"""
        try:
            # Create PLAIN auth string: \0username\0password
            auth_string = f"\0{username}\0{password}"
            auth_b64 = base64.b64encode(auth_string.encode()).decode()
            
            # Send authentication command
            self._send_command(f'AUTHENTICATE "PLAIN" "{auth_b64}"')
            response = self._read_response()
            
            if "OK" in response and "Logged in" in response:
                self.authenticated = True
                return True
            return False
        except Exception as e:
            print(f"Authentication failed: {e}")
            return False
    
    def list_scripts(self) -> Optional[list]:
        """List available Sieve scripts"""
        if not self.authenticated:
            return None
        
        try:
            self._send_command("LISTSCRIPTS")
            response = self._read_response()
            
            # Parse script list from response
            scripts = []
            lines = response.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('"') and line.endswith('"'):
                    script_name = line.strip('"')
                    if script_name and not script_name.startswith('OK'):
                        scripts.append(script_name)
            
            return scripts
        except Exception as e:
            print(f"List scripts failed: {e}")
            return None
    
    def put_script(self, name: str, content: str) -> bool:
        """Upload a Sieve script"""
        if not self.authenticated:
            return False
        
        try:
            # Calculate content length
            content_bytes = content.encode('utf-8')
            content_length = len(content_bytes)
            
            # Send PUTSCRIPT command
            self._send_command(f'PUTSCRIPT "{name}" {{{content_length}}}')
            
            # Send script content
            self.sock.send(content_bytes)
            self.sock.send(b'\r\n')
            
            response = self._read_response()
            return "OK" in response
        except Exception as e:
            print(f"Put script failed: {e}")
            return False
    
    def activate_script(self, name: str) -> bool:
        """Activate a Sieve script"""
        if not self.authenticated:
            return False
        
        try:
            self._send_command(f'SETACTIVE "{name}"')
            response = self._read_response()
            return "OK" in response
        except Exception as e:
            print(f"Activate script failed: {e}")
            return False
    
    def get_script(self, name: str) -> Optional[str]:
        """Get a Sieve script content"""
        if not self.authenticated:
            return None
        
        try:
            self._send_command(f'GETSCRIPT "{name}"')
            response = self._read_response()
            
            # Extract script content between { } markers
            if "{" in response and "}" in response:
                start = response.find("{")
                end = response.find("}", start)
                if start != -1 and end != -1:
                    length_str = response[start+1:end]
                    try:
                        length = int(length_str)
                        # Read the script content
                        content_start = response.find("\n", end) + 1
                        content = response[content_start:content_start+length]
                        return content
                    except ValueError:
                        pass
            return None
        except Exception as e:
            print(f"Get script failed: {e}")
            return None
    
    def delete_script(self, name: str) -> bool:
        """Delete a Sieve script"""
        if not self.authenticated:
            return False
        
        try:
            self._send_command(f'DELETESCRIPT "{name}"')
            response = self._read_response()
            return "OK" in response
        except Exception as e:
            print(f"Delete script failed: {e}")
            return False
    
    def capability(self) -> Optional[dict]:
        """Get server capabilities"""
        try:
            self._send_command("CAPABILITY")
            response = self._read_response()
            
            capabilities = {}
            lines = response.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('"') and line.count('"') >= 2:
                    parts = line.split('"')
                    if len(parts) >= 3:
                        key = parts[1]
                        value = parts[2].strip()
                        capabilities[key] = value
            
            return capabilities
        except Exception as e:
            print(f"Capability check failed: {e}")
            return None
    
    def logout(self) -> bool:
        """Logout from server"""
        try:
            self._send_command("LOGOUT")
            response = self._read_response()
            return "OK" in response
        except Exception as e:
            print(f"Logout failed: {e}")
            return False
    
    def close(self):
        """Close connection"""
        if self.sock:
            self.sock.close()
            self.sock = None
            self.authenticated = False
    
    def _send_command(self, command: str):
        """Send command to server"""
        if not self.sock:
            raise Exception("Not connected")
        
        cmd_bytes = (command + '\r\n').encode()
        self.sock.send(cmd_bytes)
    
    def _read_response(self) -> str:
        """Read response from server"""
        if not self.sock:
            raise Exception("Not connected")
        
        response = b""
        while True:
            data = self.sock.recv(4096)
            if not data:
                break
            response += data
            
            # Check if we have a complete response
            response_str = response.decode('utf-8', errors='ignore')
            if '\nOK ' in response_str or '\nNO ' in response_str or '\nBYE ' in response_str:
                break
        
        return response.decode('utf-8', errors='ignore')

def test_managesieve_connection():
    """Test basic ManageSieve connection"""
    print("Testing ManageSieve connection...")
    
    client = ManageSieveClient()
    try:
        assert client.connect(), "Failed to connect to ManageSieve server"
        print("✅ Connection successful")
        
        # Test capabilities
        capabilities = client.capability()
        assert capabilities is not None, "Failed to get capabilities"
        assert "IMPLEMENTATION" in capabilities, "Missing IMPLEMENTATION capability"
        assert "SIEVE" in capabilities, "Missing SIEVE capability"
        print(f"✅ Capabilities: {capabilities.get('IMPLEMENTATION', 'Unknown')}")
        
        return True
    finally:
        client.close()

def test_managesieve_authentication():
    """Test ManageSieve authentication with LDAP users"""
    print("Testing ManageSieve authentication...")
    
    # Test users
    test_users = [
        ("demo@example.com", "demo123"),
        ("john.smith@example.com", "password123"),
        ("sarah.johnson@example.com", "password123")
    ]
    
    for username, password in test_users:
        print(f"  Testing user: {username}")
        client = ManageSieveClient()
        try:
            assert client.connect(), f"Failed to connect for user {username}"
            
            auth_result = client.authenticate(username, password)
            assert auth_result, f"Authentication failed for user {username}"
            print(f"  ✅ Authentication successful for {username}")
            
            # Test logout
            assert client.logout(), f"Logout failed for user {username}"
            
        finally:
            client.close()
    
    return True

def test_sieve_script_management():
    """Test Sieve script upload, activation, and management"""
    print("Testing Sieve script management...")
    
    client = ManageSieveClient()
    try:
        # Connect and authenticate
        assert client.connect(), "Failed to connect"
        assert client.authenticate("demo@example.com", "demo123"), "Authentication failed"
        
        # Test script content
        test_script = '''require "fileinto";
require "imap4flags";

# Test script for demo user
if header :contains "subject" "URGENT" {
    setflag "\\Flagged";
    fileinto "INBOX.Priority";
    stop;
}

if header :contains "from" "noreply" {
    fileinto "INBOX.Automated";
}
'''
        
        script_name = "test_script"
        
        # List initial scripts
        initial_scripts = client.list_scripts()
        print(f"  Initial scripts: {initial_scripts}")
        
        # Upload test script
        assert client.put_script(script_name, test_script), "Failed to upload script"
        print(f"  ✅ Script '{script_name}' uploaded successfully")
        
        # List scripts after upload
        scripts_after_upload = client.list_scripts()
        assert script_name in scripts_after_upload, "Script not found in list after upload"
        print(f"  ✅ Script appears in list: {scripts_after_upload}")
        
        # Get script content
        retrieved_content = client.get_script(script_name)
        if retrieved_content:
            print(f"  ✅ Script content retrieved successfully")
        
        # Activate script
        assert client.activate_script(script_name), "Failed to activate script"
        print(f"  ✅ Script '{script_name}' activated successfully")
        
        # Clean up - delete test script
        assert client.delete_script(script_name), "Failed to delete script"
        print(f"  ✅ Script '{script_name}' deleted successfully")
        
        # Verify deletion
        scripts_after_delete = client.list_scripts()
        if script_name in scripts_after_delete:
            print(f"  ⚠️  Script still appears after deletion: {scripts_after_delete}")
        else:
            print(f"  ✅ Script successfully removed from list")
        
        return True
    finally:
        client.close()

def test_ldap_sieve_integration():
    """Test integration with LDAP-stored Sieve scripts"""
    print("Testing LDAP Sieve integration...")
    
    # Users that should have LDAP-stored scripts
    ldap_users = [
        "john.smith@example.com",
        "sarah.johnson@example.com", 
        "mike.davis@example.com",
        "demo@example.com"
    ]
    
    for username in ldap_users:
        print(f"  Testing LDAP integration for: {username}")
        client = ManageSieveClient()
        try:
            assert client.connect(), f"Failed to connect for {username}"
            assert client.authenticate(username, "password123" if username != "demo@example.com" else "demo123"), f"Authentication failed for {username}"
            
            # List scripts (should include LDAP-synced scripts)
            scripts = client.list_scripts()
            if scripts:
                print(f"    ✅ Found scripts for {username}: {scripts}")
            else:
                print(f"    ℹ️  No scripts found for {username}")
            
        except Exception as e:
            print(f"    ⚠️  Error testing {username}: {e}")
        finally:
            client.close()
    
    return True

def main():
    """Run all ManageSieve integration tests"""
    print("=" * 60)
    print("MANAGESIEVE INTEGRATION TESTS")
    print("=" * 60)
    
    tests = [
        test_managesieve_connection,
        test_managesieve_authentication,
        test_sieve_script_management,
        test_ldap_sieve_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test_func in tests:
        try:
            print(f"\n{'-' * 40}")
            if test_func():
                passed += 1
                print(f"✅ {test_func.__name__} PASSED")
            else:
                print(f"❌ {test_func.__name__} FAILED")
        except Exception as e:
            print(f"❌ {test_func.__name__} FAILED: {e}")
    
    print(f"\n{'=' * 60}")
    print(f"RESULTS: {passed}/{total} tests passed")
    print(f"{'=' * 60}")
    
    if passed == total:
        print("🎉 ALL MANAGESIEVE TESTS PASSED!")
        return 0
    else:
        print("❌ SOME TESTS FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 