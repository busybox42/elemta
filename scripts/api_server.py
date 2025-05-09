#!/usr/bin/env python3

import http.server
import socketserver
import json
import os
import random
import time
from datetime import datetime

class APIRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Log request
        print(f"Received request: {self.path}")
        
        try:
            if self.path == '/health':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode())
            elif self.path == '/api/queue/stats':
                self.serve_queue_stats()
            elif self.path == '/api/queue':
                self.serve_all_queues()
            elif self.path.startswith('/api/queue/'):
                if self.path.startswith('/api/queue/message/'):
                    msg_id = self.path.split('/')[-1]
                    self.serve_message(msg_id)
                else:
                    queue_type = self.path.split('/')[-1]
                    self.serve_queue_by_type(queue_type)
            else:
                self.send_response(404)
                self.send_header('Content-type', 'application/json')
                # Set CORS headers
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Not found", "path": self.path}).encode())
        except Exception as e:
            print(f"Error handling request: {str(e)}")
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal server error", "message": str(e)}).encode())
    
    def serve_queue_stats(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        # Set CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.end_headers()
        
        stats = {
            "active": random.randint(1, 10),
            "deferred": random.randint(1, 5),
            "hold": random.randint(0, 3),
            "failed": random.randint(0, 2)
        }
        
        self.wfile.write(json.dumps(stats).encode())
    
    def serve_all_queues(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        # Set CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.end_headers()
        
        messages = self.generate_random_messages(random.randint(5, 15))
        self.wfile.write(json.dumps(messages).encode())
    
    def serve_queue_by_type(self, queue_type):
        if queue_type not in ['active', 'deferred', 'hold', 'failed']:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            # Set CORS headers
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"Invalid queue type: {queue_type}"}).encode())
            return
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        # Set CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.end_headers()
        
        messages = self.generate_random_messages(random.randint(2, 8), queue_type)
        self.wfile.write(json.dumps(messages).encode())
    
    def generate_random_messages(self, count, queue_type=None):
        messages = []
        queue_types = ['active', 'deferred', 'hold', 'failed']
        
        for i in range(count):
            # Generate a more sophisticated message ID
            # Format: elemta-{node_id}-{timestamp}-{uuid_segment}@{hostname}
            timestamp = int(time.time() * 1000000)  # microsecond precision
            node_id = os.environ.get('NODE_ID', '0')
            uuid_segment = ''.join(random.choice('0123456789abcdef') for _ in range(12))
            hostname = os.environ.get('HOSTNAME', 'api.example.com')
            msg_id = f"elemta-{node_id}-{timestamp}-{uuid_segment}@{hostname}"
            
            from_addr = f"sender{i}@example.com"
            to_addr = f"recipient{i}@example.org"
            
            msg_type = queue_type if queue_type else random.choice(queue_types)
            
            message = {
                "id": msg_id,
                "queue_type": msg_type,
                "from": from_addr,
                "to": [to_addr],
                "subject": f"Test Message {i}",
                "size": random.randint(1024, 10240),
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "next_attempt": (datetime.now()).strftime("%Y-%m-%d %H:%M:%S") if msg_type == 'deferred' else None,
                "attempts": random.randint(0, 5) if msg_type in ['deferred', 'failed'] else 0
            }
            
            messages.append(message)
        
        return messages
    
    def serve_message(self, msg_id):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        # Set CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.end_headers()
        
        # Generate more realistic information for the message
        # If this is a generated ID using our format, extract parts for consistency
        # Otherwise just use it as-is
        from_addr = f"sender{random.randint(1, 100)}@example.com"
        to_addr = f"recipient{random.randint(1, 100)}@example.org"
        subject = f"Test Message for {msg_id.split('@')[0] if '@' in msg_id else msg_id}"
        queue_types = ['active', 'deferred', 'hold', 'failed']
        
        message = {
            "id": msg_id,
            "queue_type": random.choice(queue_types),
            "from": from_addr,
            "to": [to_addr],
            "subject": subject,
            "size": random.randint(1024, 10240),
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "content": f"From: {from_addr}\nTo: {to_addr}\nSubject: {subject}\nMessage-ID: <{msg_id}>\n\nThis is a test message with ID {msg_id}.\n\nGenerated by the Elemta API server for testing purposes.\n",
            "attempts": random.randint(0, 5),
            "next_attempt": datetime.now().strftime("%Y-%m-%d %H:%M:%S") if random.choice([True, False]) else None
        }
        
        self.wfile.write(json.dumps(message).encode())
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.end_headers()

    def do_DELETE(self):
        print(f"Received DELETE request: {self.path}")
        
        try:
            if self.path.startswith('/api/queue/message/'):
                msg_id = self.path.split('/')[-1]
                self.delete_message(msg_id)
            else:
                self.send_response(404)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Not found", "path": self.path}).encode())
        except Exception as e:
            print(f"Error handling DELETE request: {str(e)}")
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal server error", "message": str(e)}).encode())
    
    def delete_message(self, msg_id):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.end_headers()
        
        response = {
            "status": "success",
            "message": f"Message {msg_id} deleted"
        }
        
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        print(f"Received POST request: {self.path}")
        
        try:
            if self.path.endswith('/flush'):
                # Extract queue type from path
                if self.path == '/api/queue/all/flush':
                    queue_type = 'all'
                else:
                    queue_type = self.path.split('/')[-2]
                
                self.flush_queue(queue_type)
            else:
                self.send_response(404)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Not found", "path": self.path}).encode())
        except Exception as e:
            print(f"Error handling POST request: {str(e)}")
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal server error", "message": str(e)}).encode())
    
    def flush_queue(self, queue_type):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.end_headers()
        
        response = {
            "status": "success",
            "message": f"Queue {queue_type} flushed"
        }
        
        self.wfile.write(json.dumps(response).encode())

def run_server(port=8081):
    handler = APIRequestHandler
    httpd = socketserver.TCPServer(("", port), handler)
    print(f"Starting API server on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    # Get port from environment or use default
    port = int(os.environ.get("API_PORT", 8081))
    run_server(port) 