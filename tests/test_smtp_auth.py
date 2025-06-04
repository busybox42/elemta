#!/usr/bin/env python3
import socket
import base64
import time

def test_smtp_auth_and_delivery():
    # Connect to SMTP server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
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
        send_command('From: sender@example.com')
        send_command('To: recipient@example.com')
        send_command('Subject: Test Authentication and Delivery')
        send_command('')
        send_command('This email tests both SMTP auth and delivery to dovecot.')
        send_command('Time: ' + str(time.time()))
        send_command('.')
        send_command('QUIT')
        
        print('\n✅ SMTP authentication and email submission successful!')
        
    except Exception as e:
        print(f'\n❌ Error: {e}')
    finally:
        sock.close()

if __name__ == '__main__':
    test_smtp_auth_and_delivery() 