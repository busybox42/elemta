import http.server
import random
import time
import threading
import socket
import socketserver
from datetime import datetime

class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
            # Generate random metrics for testing
            connections = random.randint(1, 100)
            messages_received = random.randint(1, 1000)
            messages_delivered = random.randint(1, messages_received)
            messages_failed = messages_received - messages_delivered
            queue_size = random.randint(1, 500)
            
            # SMTP server metrics
            self.wfile.write(b"# HELP elemta_connections_total Total number of SMTP connections\n")
            self.wfile.write(b"# TYPE elemta_connections_total counter\n")
            self.wfile.write(f"elemta_connections_total {connections}\n".encode())
            
            self.wfile.write(b"# HELP elemta_connections_active Current active SMTP connections\n")
            self.wfile.write(b"# TYPE elemta_connections_active gauge\n")
            self.wfile.write(f"elemta_connections_active {random.randint(1, connections)}\n".encode())
            
            self.wfile.write(b"# HELP elemta_messages_received_total Total messages received\n")
            self.wfile.write(b"# TYPE elemta_messages_received_total counter\n")
            self.wfile.write(f"elemta_messages_received_total {messages_received}\n".encode())
            
            self.wfile.write(b"# HELP elemta_messages_delivered_total Total messages delivered\n")
            self.wfile.write(b"# TYPE elemta_messages_delivered_total counter\n")
            self.wfile.write(f"elemta_messages_delivered_total {messages_delivered}\n".encode())
            
            self.wfile.write(b"# HELP elemta_messages_failed_total Total messages that failed delivery\n")
            self.wfile.write(b"# TYPE elemta_messages_failed_total counter\n")
            self.wfile.write(f"elemta_messages_failed_total {messages_failed}\n".encode())
            
            # Queue metrics
            self.wfile.write(b"# HELP elemta_queue_size Size of the queue\n")
            self.wfile.write(b"# TYPE elemta_queue_size gauge\n")
            self.wfile.write(f"elemta_queue_size{{queue=\"active\"}} {random.randint(1, queue_size)}\n".encode())
            self.wfile.write(f"elemta_queue_size{{queue=\"deferred\"}} {random.randint(1, queue_size)}\n".encode())
            self.wfile.write(f"elemta_queue_size{{queue=\"held\"}} {random.randint(1, queue_size)}\n".encode())
            self.wfile.write(f"elemta_queue_size{{queue=\"failed\"}} {random.randint(1, queue_size)}\n".encode())
            
            # Security metrics
            auth_attempts = random.randint(1, 500)
            auth_successes = random.randint(1, auth_attempts)
            
            self.wfile.write(b"# HELP elemta_auth_attempts_total Total authentication attempts\n")
            self.wfile.write(b"# TYPE elemta_auth_attempts_total counter\n")
            self.wfile.write(f"elemta_auth_attempts_total {auth_attempts}\n".encode())
            
            self.wfile.write(b"# HELP elemta_auth_successes_total Total successful authentications\n")
            self.wfile.write(b"# TYPE elemta_auth_successes_total counter\n")
            self.wfile.write(f"elemta_auth_successes_total {auth_successes}\n".encode())
            
            self.wfile.write(b"# HELP elemta_auth_failures_total Total failed authentications\n")
            self.wfile.write(b"# TYPE elemta_auth_failures_total counter\n")
            self.wfile.write(f"elemta_auth_failures_total {auth_attempts - auth_successes}\n".encode())
            
            # Plugin metrics
            self.wfile.write(b"# HELP elemta_plugin_execution_total Total plugin executions\n")
            self.wfile.write(b"# TYPE elemta_plugin_execution_total counter\n")
            self.wfile.write(f"elemta_plugin_execution_total{{plugin=\"example_greylisting\"}} {random.randint(1, 1000)}\n".encode())
            
            # Greylisting metrics
            greylisted_total = random.randint(1, 500)
            
            self.wfile.write(b"# HELP elemta_greylisting_total Total greylisted messages\n")
            self.wfile.write(b"# TYPE elemta_greylisting_total counter\n")
            self.wfile.write(f"elemta_greylisting_total {greylisted_total}\n".encode())
            
            self.wfile.write(b"# HELP elemta_greylisting_passed Total messages that passed greylisting\n")
            self.wfile.write(b"# TYPE elemta_greylisting_passed counter\n")
            self.wfile.write(f"elemta_greylisting_passed {random.randint(1, greylisted_total)}\n".encode())
            
            self.wfile.write(b"# HELP elemta_greylisting_active_entries Current entries in the greylisting database\n")
            self.wfile.write(b"# TYPE elemta_greylisting_active_entries gauge\n")
            self.wfile.write(f"elemta_greylisting_active_entries {random.randint(1, 1000)}\n".encode())
            
            # ClamAV metrics
            clamav_scans = random.randint(1, 1000)
            
            self.wfile.write(b"# HELP elemta_clamav_scans_total Total number of ClamAV scans\n")
            self.wfile.write(b"# TYPE elemta_clamav_scans_total counter\n")
            self.wfile.write(f"elemta_clamav_scans_total {clamav_scans}\n".encode())
            
            self.wfile.write(b"# HELP elemta_clamav_virus_detected_total Total number of viruses detected\n")
            self.wfile.write(b"# TYPE elemta_clamav_virus_detected_total counter\n")
            self.wfile.write(f"elemta_clamav_virus_detected_total {random.randint(1, clamav_scans // 10)}\n".encode())
            
            # Rspamd metrics
            rspamd_scans = random.randint(1, 1000)
            
            self.wfile.write(b"# HELP elemta_rspamd_scans_total Total number of Rspamd scans\n")
            self.wfile.write(b"# TYPE elemta_rspamd_scans_total counter\n")
            self.wfile.write(f"elemta_rspamd_scans_total {rspamd_scans}\n".encode())
            
            self.wfile.write(b"# HELP elemta_rspamd_spam_total Total number of spam messages detected\n")
            self.wfile.write(b"# TYPE elemta_rspamd_spam_total counter\n")
            self.wfile.write(f"elemta_rspamd_spam_total {random.randint(1, rspamd_scans // 3)}\n".encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def log_message(self, format, *args):
        # Suppress log messages
        pass

class SMTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Send greeting
        self.request.sendall(b"220 elemta.local ESMTP Elemta Mock Server\r\n")
        
        while True:
            try:
                data = self.request.recv(1024).strip()
                if not data:
                    break
                
                data_str = data.decode('utf-8').upper()
                
                # Handle QUIT command
                if data_str.startswith('QUIT'):
                    self.request.sendall(b"221 Bye\r\n")
                    break
                
                # Handle EHLO/HELO
                elif data_str.startswith('EHLO') or data_str.startswith('HELO'):
                    self.request.sendall(b"250-elemta.local\r\n")
                    self.request.sendall(b"250-SIZE 52428800\r\n")
                    self.request.sendall(b"250-8BITMIME\r\n")
                    self.request.sendall(b"250-PIPELINING\r\n")
                    self.request.sendall(b"250 HELP\r\n")
                
                # Handle MAIL FROM
                elif data_str.startswith('MAIL FROM'):
                    self.request.sendall(b"250 OK\r\n")
                
                # Handle RCPT TO
                elif data_str.startswith('RCPT TO'):
                    self.request.sendall(b"250 OK\r\n")
                
                # Handle DATA
                elif data_str.startswith('DATA'):
                    self.request.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    # Wait for message body and the terminating "."
                    while True:
                        msg_data = self.request.recv(1024)
                        if not msg_data:
                            break
                        if msg_data.endswith(b"\r\n.\r\n"):
                            break
                    self.request.sendall(b"250 OK: message accepted for delivery\r\n")
                
                # Handle other commands
                else:
                    self.request.sendall(b"250 OK\r\n")
                    
            except Exception as e:
                print(f"Error handling SMTP connection: {e}")
                break

def run_metrics_server():
    server_address = ('', 8080)
    httpd = http.server.HTTPServer(server_address, MetricsHandler)
    print('Starting metrics server on port 8080...')
    httpd.serve_forever()

def run_smtp_server():
    server = socketserver.ThreadingTCPServer(('', 25), SMTPHandler)
    print('Starting SMTP server on port 25...')
    server.serve_forever()

if __name__ == '__main__':
    # Start metrics server in a separate thread
    metrics_thread = threading.Thread(target=run_metrics_server)
    metrics_thread.daemon = True
    metrics_thread.start()
    
    # Run SMTP server in the main thread
    run_smtp_server() 