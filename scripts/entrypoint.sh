#!/bin/bash

# Simple entrypoint script for testing purposes

echo "Starting Elemta SMTP server mock for monitoring testing..."

# Create a simple metrics endpoint
cat > /app/metrics_server.py << EOF
import http.server
import random
import time
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
            self.wfile.write(f"elemta_queue_size{{queue_type=\"active\"}} {random.randint(1, queue_size)}\n".encode())
            self.wfile.write(f"elemta_queue_size{{queue_type=\"deferred\"}} {random.randint(1, queue_size)}\n".encode())
            self.wfile.write(f"elemta_queue_size{{queue_type=\"held\"}} {random.randint(1, queue_size)}\n".encode())
            self.wfile.write(f"elemta_queue_size{{queue_type=\"failed\"}} {random.randint(1, queue_size)}\n".encode())
            
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

if __name__ == '__main__':
    server_address = ('', 8080)
    httpd = http.server.HTTPServer(server_address, MetricsHandler)
    print('Starting metrics server on port 8080...')
    httpd.serve_forever()
EOF

# Run the metrics server
python3 /app/metrics_server.py 