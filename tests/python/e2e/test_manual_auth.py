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
    assert "235" in response  # 235 = Authentication successful
    
    # Quit session
    response = send_command("QUIT")
    assert "221" in response
    
    sock.close()

def test_manual_auth_plain(smtp_host, smtp_port):
    """Test SMTP AUTH PLAIN using raw socket communication."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((smtp_host, smtp_port))
    
    # Buffer for reading responses
    def read_response():
        response = b""
        while True:
            data = sock.recv(1024)
            response += data
            if len(data) < 1024 or b"\r\n" in data:
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
    assert "250" in response
    assert "AUTH" in response
    
    # Make sure we've received the full EHLO response
    # The server can send multi-line responses for EHLO
    if "HELP" not in response:
        # Receive the rest of the EHLO response
        while True:
            try:
                data = sock.recv(1024)
                if not data:
                    break
                part = data.decode('utf-8').strip()
                print(f"<<< (continued) {part}")
                response += "\n" + part
                if "HELP" in part:
                    break
            except socket.timeout:
                break
    
    # Test one-step AUTH PLAIN approach
    print("\n--- Trying AUTH PLAIN with one-step approach ---")
    auth_data = b"\0testuser\0testpass"
    print(f"Auth data (hex): {binascii.hexlify(auth_data)}")
    auth_b64 = base64.b64encode(auth_data).decode('utf-8')
    response = send_command(f"AUTH PLAIN {auth_b64}")
    success = "235" in response
    print(f"Success with one-step approach: {success}")
    
    if not success:
        # Try two-step approach as fallback
        print("\n--- Trying AUTH PLAIN with two-step approach ---")
        response = send_command("AUTH PLAIN")
        assert "334" in response
        
        response = send_command(auth_b64)
        success = "235" in response
        print(f"Success with two-step approach: {success}")
    
    assert success, "AUTH PLAIN failed"
    
    # Quit session
    response = send_command("QUIT")
    assert "221" in response
    
    sock.close() 