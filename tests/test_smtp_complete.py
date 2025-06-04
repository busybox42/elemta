#!/usr/bin/env python3
import socket
import base64
import time

def test_complete_smtp_flow():
    # Connect to SMTP server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect(('localhost', 2525))

    def read_response():
        data = sock.recv(4096)
        response = data.decode().strip()
        print('<<<', response)
        return response

    def send_command(cmd):
        print('>>>', cmd)
        sock.send((cmd + '\r\n').encode())
        return read_response()

    try:
        # SMTP conversation
        read_response()  # greeting
        send_command('EHLO test.com')
        
        # Test authentication
        auth_string = base64.b64encode(b'\x00sender@example.com\x00password').decode()
        send_command('AUTH PLAIN ' + auth_string)
        
        # Send test email
        send_command('MAIL FROM:<sender@example.com>')
        send_command('RCPT TO:<recipient@example.com>')
        send_command('DATA')
        
        # Send email headers and body
        sock.send(b'From: sender@example.com\r\n')
        sock.send(b'To: recipient@example.com\r\n')
        sock.send(b'Subject: Test Authentication and Delivery\r\n')
        sock.send(b'\r\n')
        sock.send(b'This email tests both SMTP auth and delivery to dovecot.\r\n')
        sock.send(b'Time: ' + str(time.time()).encode() + b'\r\n')
        sock.send(b'.\r\n')  # End of message
        
        # Read the response to DATA completion
        response = read_response()
        print('DATA response:', response)
        
        send_command('QUIT')
        
        print('\n✅ SMTP authentication and email delivery test completed!')
        
    except Exception as e:
        print(f'\n❌ Error: {e}')
    finally:
        sock.close()

if __name__ == '__main__':
    test_complete_smtp_flow() 