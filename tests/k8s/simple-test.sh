#!/bin/bash

echo "Starting simple test..."
echo "Current directory: $(pwd)"
echo "Current user: $(whoami)"
echo "Date and time: $(date)"

echo "Testing SMTP connection..."
nc -zv localhost 30025 || echo "SMTP port not accessible"

echo "Testing Rspamd connection..."
nc -zv localhost 30334 || echo "Rspamd port not accessible"

echo "Test completed." 