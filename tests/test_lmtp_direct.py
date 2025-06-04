#!/usr/bin/env python3
import socket
import time

def test_lmtp_delivery():
    # Connect to dovecot LMTP server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    
    try:
        sock.connect(('elemta-dovecot', 2424))
        print("✅ Connected to dovecot LMTP server")
    except Exception as e:
        print(f"❌ Failed to connect to dovecot LMTP: {e}")
        try:
            sock.connect(('localhost', 2424))
            print("✅ Connected to localhost LMTP server")
        except Exception as e2:
            print(f"❌ Failed to connect to localhost LMTP: {e2}")
            return

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
        # LMTP conversation
        read_response()  # greeting
        send_command('LHLO mail.example.com')
        
        # Send test email
        send_command('MAIL FROM:<sender@example.com>')
        send_command('RCPT TO:<recipient@example.com>')
        send_command('DATA')
        
        # Send email headers and body
        sock.send(b'From: sender@example.com\r\n')
        sock.send(b'To: recipient@example.com\r\n')
        sock.send(b'Subject: Direct LMTP Test\r\n')
        sock.send(b'\r\n')
        sock.send(b'This email tests direct LMTP delivery to dovecot.\r\n')
        sock.send(b'Time: ' + str(time.time()).encode() + b'\r\n')
        sock.send(b'.\r\n')  # End of message
        
        # Read the response to DATA completion
        response = read_response()
        print('DATA response:', response)
        
        send_command('QUIT')
        
        print('\n✅ Direct LMTP delivery test completed!')
        
    except Exception as e:
        print(f'\n❌ Error: {e}')
    finally:
        sock.close()

if __name__ == '__main__':
    test_lmtp_delivery() 