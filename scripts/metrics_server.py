#!/usr/bin/env python3
"""
Simple metrics server for Elemta that exposes Prometheus metrics.
This is used for testing the monitoring stack.
"""

import http.server
import random
import time
import os
import ssl
from threading import Thread
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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
    "elemta_rspamd_ham_total": 0,
    "elemta_tls_certificate_expiry_seconds": 0,
    "elemta_tls_certificate_valid": 0,
    "elemta_letsencrypt_renewal_status": 1,
    "elemta_letsencrypt_renewal_attempts_total": 0,
    "elemta_letsencrypt_last_renewal_timestamp": 0
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

def check_certificate(cert_path):
    """Check certificate and return expiry seconds and validity."""
    try:
        if os.path.exists(cert_path):
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            now = datetime.now(timezone.utc)
            expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)
            
            seconds_until_expiry = (expiry - now).total_seconds()
            is_valid = 1 if (now >= cert.not_valid_before.replace(tzinfo=timezone.utc) and now <= expiry) else 0
            
            return seconds_until_expiry, is_valid
        else:
            # If no cert, return a simulated 30-day cert
            return 30 * 24 * 3600, 1
    except Exception as e:
        print(f"Error checking certificate: {e}")
        return 30 * 24 * 3600, 1

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
        
        # Update certificate metrics
        cert_path = "/app/certs/fullchain.pem"
        expiry_seconds, is_valid = check_certificate(cert_path)
        metrics["elemta_tls_certificate_expiry_seconds"] = expiry_seconds
        metrics["elemta_tls_certificate_valid"] = is_valid
        
        # Simulate Let's Encrypt renewal metrics
        metrics["elemta_letsencrypt_renewal_status"] = 1  # Success
        metrics["elemta_letsencrypt_last_renewal_timestamp"] = int(time.time())
        if random.randint(1, 100) <= 5:  # 5% chance to increment renewal attempts
            metrics["elemta_letsencrypt_renewal_attempts_total"] += 1
        
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