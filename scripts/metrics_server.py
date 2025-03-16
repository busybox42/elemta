#!/usr/bin/env python3
"""
Simple metrics server for Elemta that exposes Prometheus metrics.
This is used for testing the monitoring stack.
"""

import http.server
import random
import time
from threading import Thread

# Metrics that will be exposed
metrics = {
    "elemta_connections_active": 0,
    "elemta_connections_total": 0,
    "elemta_messages_received_total": 0,
    "elemta_messages_delivered_total": 0,
    "elemta_messages_failed_total": 0,
    "elemta_queue_size": 0,
    "elemta_delivery_attempts_total": 0,
    "elemta_delivery_successes_total": 0,
    "elemta_delivery_failures_total": 0,
    "elemta_authentication_successes_total": 0,
    "elemta_authentication_failures_total": 0,
    "elemta_tls_connections_total": 0,
    "elemta_greylisting_delayed_total": 0,
    "elemta_greylisting_allowed_total": 0,
    "elemta_clamav_scans_total": 0,
    "elemta_clamav_detections_total": 0,
    "elemta_rspamd_scans_total": 0,
    "elemta_rspamd_spam_total": 0,
    "elemta_rspamd_ham_total": 0
}

class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
            # Generate metrics output
            output = ""
            for metric, value in metrics.items():
                output += f"# HELP {metric} Elemta {metric.replace('elemta_', '').replace('_', ' ')}.\n"
                output += f"# TYPE {metric} gauge\n"
                output += f"{metric} {value}\n"
            
            self.wfile.write(output.encode())
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><head><title>Elemta Metrics</title></head>")
            self.wfile.write(b"<body><h1>Elemta Metrics Server</h1>")
            self.wfile.write(b"<p>Visit <a href='/metrics'>/metrics</a> for Prometheus metrics.</p>")
            self.wfile.write(b"</body></html>")

def update_metrics():
    """Update metrics with random values to simulate activity."""
    while True:
        # Simulate connections
        metrics["elemta_connections_active"] = random.randint(5, 50)
        metrics["elemta_connections_total"] += random.randint(1, 10)
        
        # Simulate messages
        new_messages = random.randint(1, 20)
        metrics["elemta_messages_received_total"] += new_messages
        
        delivered = random.randint(1, new_messages)
        metrics["elemta_messages_delivered_total"] += delivered
        
        failed = random.randint(0, new_messages - delivered)
        metrics["elemta_messages_failed_total"] += failed
        
        # Simulate queue
        metrics["elemta_queue_size"] = random.randint(10, 200)
        
        # Simulate delivery attempts
        attempts = random.randint(5, 30)
        metrics["elemta_delivery_attempts_total"] += attempts
        
        successes = random.randint(1, attempts)
        metrics["elemta_delivery_successes_total"] += successes
        
        failures = attempts - successes
        metrics["elemta_delivery_failures_total"] += failures
        
        # Simulate authentication
        auth_attempts = random.randint(1, 15)
        auth_successes = random.randint(1, auth_attempts)
        metrics["elemta_authentication_successes_total"] += auth_successes
        metrics["elemta_authentication_failures_total"] += (auth_attempts - auth_successes)
        
        # Simulate TLS
        metrics["elemta_tls_connections_total"] += random.randint(1, 10)
        
        # Simulate greylisting
        greylist_total = random.randint(1, 10)
        metrics["elemta_greylisting_delayed_total"] += greylist_total
        metrics["elemta_greylisting_allowed_total"] += random.randint(1, greylist_total)
        
        # Simulate security scanning
        clamav_scans = random.randint(5, 25)
        metrics["elemta_clamav_scans_total"] += clamav_scans
        metrics["elemta_clamav_detections_total"] += random.randint(0, 2)
        
        rspamd_scans = random.randint(5, 25)
        metrics["elemta_rspamd_scans_total"] += rspamd_scans
        metrics["elemta_rspamd_spam_total"] += random.randint(0, 3)
        metrics["elemta_rspamd_ham_total"] += (rspamd_scans - random.randint(0, 3))
        
        time.sleep(5)

def main():
    # Start the metrics updater thread
    updater = Thread(target=update_metrics)
    updater.daemon = True
    updater.start()
    
    # Start the HTTP server
    server_address = ('', 8080)
    httpd = http.server.HTTPServer(server_address, MetricsHandler)
    print("Starting metrics server on port 8080...")
    httpd.serve_forever()

if __name__ == "__main__":
    main() 