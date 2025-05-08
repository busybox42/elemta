#!/bin/sh

# Entrypoint script for Elemta

echo "Starting Elemta SMTP server..."

# Workaround: copy TOML config to .conf if present
if [ -f /app/config/elemta.toml ]; then
    cp /app/config/elemta.toml /app/config/elemta.conf
fi

# Create test messages in the queue if TEST_MODE is enabled
if [ "$TEST_MODE" = "true" ]; then
    echo "TEST MODE ENABLED: Creating test messages in the queue..."
    
    # Ensure queue directories exist
    mkdir -p /app/queue/active
    mkdir -p /app/queue/deferred
    mkdir -p /app/queue/hold
    mkdir -p /app/queue/failed
    
    # Generate a few sample messages with random data
    for i in {1..5}; do
        msg_id=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
        timestamp=$(date +%s)
        
        # Create message file in active queue
        cat > "/app/queue/active/msg-${msg_id}.eml" << EOF
From: sender${i}@example.com
To: recipient${i}@example.org
Subject: Test Message ${i}
Date: $(date -R)
Message-ID: <${msg_id}@elemta.local>

This is test message ${i} created automatically by Elemta in test mode.
This message was created at $(date).
EOF
        echo "Created test message ${i} with ID ${msg_id} in active queue"
    done
    
    # Create a few deferred messages
    for i in {1..3}; do
        msg_id=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
        timestamp=$(date +%s)
        future_timestamp=$((timestamp + 1800)) # 30 minutes in seconds
        
        # Create message file in deferred queue
        cat > "/app/queue/deferred/msg-${msg_id}.eml" << EOF
From: deferred${i}@example.com
To: unreachable${i}@example.net
Subject: Deferred Test Message ${i}
Date: $(date -R)
Message-ID: <${msg_id}@elemta.local>
X-Elemta-Defer-Count: 2
X-Elemta-Next-Attempt: $(date -R -d "@$future_timestamp")

This is a deferred test message ${i} created automatically by Elemta in test mode.
This message was created at $(date) and will be retried later.
EOF
        echo "Created deferred test message ${i} with ID ${msg_id}"
    done
    
    # Create a held message
    msg_id=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
    cat > "/app/queue/hold/msg-${msg_id}.eml" << EOF
From: suspicious@example.com
To: admin@example.org
Subject: [HELD] Suspicious Message
Date: $(date -R)
Message-ID: <${msg_id}@elemta.local>
X-Elemta-Hold-Reason: Suspicious content detected

This message was automatically held by Elemta's content filter.
It contains suspicious content that requires administrator review.
EOF
    echo "Created held message with ID ${msg_id}"
    
    # Create a failed message
    msg_id=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
    cat > "/app/queue/failed/msg-${msg_id}.eml" << EOF
From: failure@example.com
To: nonexistent@invalid.example
Subject: [FAILED] Delivery Failure
Date: $(date -R)
Message-ID: <${msg_id}@elemta.local>
X-Elemta-Failure-Reason: Permanent failure - recipient does not exist

This is a failed message that could not be delivered after multiple attempts.
The recipient domain does not exist or the recipient was rejected.
EOF
    echo "Created failed message with ID ${msg_id}"
    
    echo "Finished creating test messages"
fi

# Check if we have the actual Go binary
ls -la /app/elemta
if [ -x "/app/elemta" ]; then
    echo "Found elemta binary, using that instead of mock server"
    
    # Start the API server in background if enabled
    if [ -f "/app/api_server.py" ] && [ "$API_ENABLED" != "false" ]; then
        echo "Starting API server in background..."
        python3 /app/api_server.py &
        API_PID=$!
        echo "API server started with PID: $API_PID"
        
        # Wait a moment for API server to start
        sleep 2
        
        # Setup trap to kill API server on exit
        trap 'kill $API_PID; exit' TERM INT
    fi
    
    # Check if we need to run elemta-cli
    if [ "$1" = "cli" ]; then
        shift
        echo "Running elemta-cli with args: $@"
        exec /app/elemta-cli "$@"
    # Check if we need to start as a server or handle other commands
    elif [ "$1" = "server" ]; then
        echo "Starting elemta server..."
        exec /app/elemta server
    else
        # If any arguments were provided, run the elemta binary with them
        if [ $# -gt 0 ]; then
            echo "Running elemta with args: $@"
            exec /app/elemta "$@"
        else
            # Default to starting the server if no arguments
            echo "Starting elemta server with no args..."
            exec /app/elemta server
        fi
    fi
    
    exit 0
fi

# If we reach here, no binary was found so we create mock servers
echo "No elemta binary found, creating mock servers for testing"

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

# Create a simple SMTP server
cat > /app/smtp_server.py << EOF
import asyncio
import logging
import sys
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger('elemta-smtp')

class SMTPProtocol(asyncio.Protocol):
    def __init__(self):
        self.buffer = b''
        self.transport = None
        self.client_address = None
        self.state = 'INIT'
        self.mail_from = None
        self.rcpt_to = []
        self.data_buffer = []
        self.logger = logger

    def connection_made(self, transport):
        self.transport = transport
        self.client_address = transport.get_extra_info('peername')
        self.logger.info(f"Connection from {self.client_address}")
        self.send_response(220, "elemta.local ESMTP Elemta ready")
        self.state = 'GREETING'

    def data_received(self, data):
        self.buffer += data
        if b'\r\n' in self.buffer:
            lines = self.buffer.split(b'\r\n')
            self.buffer = lines.pop()  # Keep incomplete line in buffer
            for line in lines:
                try:
                    self.process_command(line.decode('utf-8'))
                except UnicodeDecodeError:
                    self.send_response(500, "Invalid command encoding")

    def connection_lost(self, exc):
        self.logger.info(f"Connection closed from {self.client_address}")

    def process_command(self, line):
        if not line:
            return
            
        self.logger.info(f"Received: {line}")
        
        parts = line.split(' ', 1)
        command = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""
        
        if self.state == 'DATA':
            if line == '.':
                # End of data
                message = '\\n'.join(self.data_buffer)
                self.logger.info(f"Received message from {self.mail_from} to {self.rcpt_to}")
                self.send_response(250, "OK: message accepted for delivery")
                self.state = 'GREETING'
                self.mail_from = None
                self.rcpt_to = []
                self.data_buffer = []
            else:
                # Collect message data
                if line.startswith('.'):
                    line = line[1:]  # Remove dot-stuffing
                self.data_buffer.append(line)
            return
            
        if command == 'HELO' or command == 'EHLO':
            self.handle_helo(args)
        elif command == 'MAIL':
            self.handle_mail(args)
        elif command == 'RCPT':
            self.handle_rcpt(args)
        elif command == 'DATA':
            self.handle_data()
        elif command == 'QUIT':
            self.handle_quit()
        elif command == 'RSET':
            self.handle_rset()
        elif command == 'NOOP':
            self.send_response(250, "OK")
        elif command == 'HELP':
            self.send_response(214, "HELO EHLO MAIL RCPT DATA RSET NOOP QUIT HELP")
        else:
            self.send_response(502, "Command not implemented")

    def handle_helo(self, args):
        if not args:
            self.send_response(501, "Syntax: HELO hostname")
            return
            
        self.send_response(250, f"elemta.local Hello {args}")
        self.state = 'MAIL'

    def handle_mail(self, args):
        if self.state != 'MAIL':
            self.send_response(503, "Bad sequence of commands")
            return
            
        if not args.startswith('FROM:'):
            self.send_response(501, "Syntax: MAIL FROM:<address>")
            return
            
        # Extract email from FROM:<email>
        try:
            email = args[5:].strip()
            if email.startswith('<') and email.endswith('>'):
                email = email[1:-1]
            self.mail_from = email
            self.send_response(250, "OK")
            self.state = 'RCPT'
        except Exception as e:
            self.logger.error(f"Error parsing MAIL FROM: {e}")
            self.send_response(501, "Syntax error in parameters")

    def handle_rcpt(self, args):
        if self.state != 'RCPT' and self.state != 'DATA_READY':
            self.send_response(503, "Bad sequence of commands")
            return
            
        if not args.startswith('TO:'):
            self.send_response(501, "Syntax: RCPT TO:<address>")
            return
            
        # Extract email from TO:<email>
        try:
            email = args[3:].strip()
            if email.startswith('<') and email.endswith('>'):
                email = email[1:-1]
            self.rcpt_to.append(email)
            self.send_response(250, "OK")
            self.state = 'DATA_READY'
        except Exception as e:
            self.logger.error(f"Error parsing RCPT TO: {e}")
            self.send_response(501, "Syntax error in parameters")

    def handle_data(self):
        if self.state != 'DATA_READY':
            self.send_response(503, "Bad sequence of commands")
            return
            
        self.send_response(354, "End data with <CR><LF>.<CR><LF>")
        self.state = 'DATA'

    def handle_rset(self):
        self.mail_from = None
        self.rcpt_to = []
        self.data_buffer = []
        self.state = 'MAIL'
        self.send_response(250, "OK")

    def handle_quit(self):
        self.send_response(221, "elemta.local Service closing transmission channel")
        self.transport.close()

    def send_response(self, code, message):
        response = f"{code} {message}\r\n"
        self.logger.info(f"Sending: {response.strip()}")
        self.transport.write(response.encode('utf-8'))

async def start_smtp_server():
    loop = asyncio.get_event_loop()
    server = await loop.create_server(
        SMTPProtocol,
        '0.0.0.0',
        25
    )
    logger.info("Starting SMTP server on port 25...")
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(start_smtp_server())
EOF

# Run both servers
echo "Starting mock SMTP and metrics servers..."
python3 /app/metrics_server.py &
python3 /app/smtp_server.py 