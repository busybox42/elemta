import socket
import pytest
import base64
import binascii

def test_manual_auth_login(smtp_host, smtp_port):
    """Test SMTP AUTH LOGIN using raw socket communication."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((smtp_host, smtp_port))
    sock.settimeout(3)  # Set a timeout to prevent hanging
    
    # Buffer for reading responses
    def read_response():
        response = b""
        while True:
            try:
                data = sock.recv(1024)
                if not data:
                    break
                response += data
                if b"\r\n" in data and not (data.endswith(b"-") or response.endswith(b"-\r\n")):
                    break
            except socket.timeout:
                break
        print(f"<<< {response.decode('utf-8').strip()}")
        return response.decode('utf-8').strip()
    
    # Send a command and print it
    def send_command(command):
        print(f">>> {command}")
        sock.send(f"{command}\r\n".encode('utf-8'))
        return read_response()
    
    # Initial greeting
    response = read_response()
    assert "220" in response
    
    # Start session
    response = send_command("EHLO test")
    
    # Read additional response lines if needed
    while "250 " not in response and "250-" in response:
        try:
            more_data = sock.recv(1024)
            if more_data:
                more_text = more_data.decode('utf-8').strip()
                print(f"<<< (continued) {more_text}")
                response += "\n" + more_text
            else:
                break
        except socket.timeout:
            break
    
    assert "250" in response
    assert "AUTH" in response or "AUTH PLAIN LOGIN" in response
    
    # AUTH LOGIN command
    response = send_command("AUTH LOGIN")
    assert "334" in response
    
    # Send base64 encoded username
    username_b64 = base64.b64encode(b"testuser").decode('utf-8')
    response = send_command(username_b64)
    assert "334" in response
    
    # Send base64 encoded password
    password_b64 = base64.b64encode(b"testpass").decode('utf-8')
    response = send_command(password_b64)
    
    # Auth is expected to fail with these credentials
    assert "535" in response
    print("Authentication failed as expected with invalid credentials")
    
    # Quit session
    response = send_command("QUIT")
    assert "221" in response
    
    sock.close()

def test_manual_auth_plain(smtp_host, smtp_port):
    """Test SMTP AUTH PLAIN using raw socket communication."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((smtp_host, smtp_port))
    sock.settimeout(3)  # Add timeout
    
    # Buffer for reading responses
    def read_response():
        response = b""
        while True:
            try:
                data = sock.recv(1024)
                if not data:
                    break
                response += data
                if b"\r\n" in data and not (data.endswith(b"-") or response.endswith(b"-\r\n")):
                    break
            except socket.timeout:
                break
        print(f"<<< {response.decode('utf-8').strip()}")
        return response.decode('utf-8').strip()
    
    # Send a command and print it
    def send_command(command):
        print(f">>> {command}")
        sock.send(f"{command}\r\n".encode('utf-8'))
        return read_response()
    
    # Initial greeting
    response = read_response()
    assert "220" in response
    
    # Start session
    response = send_command("EHLO test")
    
    # Read additional response lines if needed
    while "250 " not in response and "250-" in response:
        try:
            more_data = sock.recv(1024)
            if more_data:
                more_text = more_data.decode('utf-8').strip()
                print(f"<<< (continued) {more_text}")
                response += "\n" + more_text
            else:
                break
        except socket.timeout:
            break
    
    assert "250" in response
    # Look for AUTH in the entire response
    assert "AUTH" in response or "AUTH PLAIN LOGIN" in response
    
    # Test one-step AUTH PLAIN approach
    print("\n--- Trying AUTH PLAIN with one-step approach ---")
    auth_data = b"\0testuser\0testpass"
    print(f"Auth data (hex): {binascii.hexlify(auth_data)}")
    auth_b64 = base64.b64encode(auth_data).decode('utf-8')
    response = send_command(f"AUTH PLAIN {auth_b64}")
    # Check for authentication failure (535)
    failure_one_step = "535" in response
    print(f"Authentication failed with one-step approach as expected: {failure_one_step}")
    
    assert failure_one_step, "Expected authentication to fail with invalid credentials"
    
    # Try two-step approach as well
    print("\n--- Trying AUTH PLAIN with two-step approach ---")
    response = send_command("AUTH PLAIN")
    assert "334" in response
    
    response = send_command(auth_b64)
    # Check for authentication failure (535)
    failure_two_step = "535" in response
    print(f"Authentication failed with two-step approach as expected: {failure_two_step}")
    
    assert failure_two_step, "Expected authentication to fail with invalid credentials"
    
    # Quit session
    response = send_command("QUIT")
    assert "221" in response
    
    sock.close() 