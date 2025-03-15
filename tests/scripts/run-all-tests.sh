#!/bin/bash

# Run all tests and report results
echo "Running Elemta MTA tests..."
echo "============================"

# Check if Docker containers are running
echo "Checking Docker containers..."
CONTAINERS=$(docker ps --format "{{.Names}}" | grep -E 'elemta|elemta-clamav|elemta-rspamd')
if [ -z "$CONTAINERS" ]; then
    echo "ERROR: Docker containers are not running. Please start them with 'make docker-deploy'."
    exit 1
fi
echo "Docker containers are running."
echo ""

# Run basic email test
echo "Running basic email test..."
go run tests/scripts/email/test-email.go
if [ $? -eq 0 ]; then
    echo "✅ Basic email test passed."
else
    echo "❌ Basic email test failed."
fi
echo ""

# Run spam test
echo "Running spam detection test..."
go run tests/scripts/spam/spam-test.go
if [ $? -eq 0 ]; then
    echo "✅ Spam detection test passed."
else
    echo "❌ Spam detection test failed."
fi
echo ""

# Run virus test
echo "Running virus detection test..."
go run tests/scripts/virus/virus-test.go
if [ $? -eq 0 ]; then
    echo "✅ Virus detection test passed."
else
    echo "❌ Virus detection test failed."
fi
echo ""

echo "All tests completed."
echo "============================" 