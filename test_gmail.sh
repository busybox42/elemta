#!/bin/bash

# Replace with your actual Gmail address
GMAIL_ADDRESS="your.email@gmail.com"

# Connect to the SMTP server
{
  sleep 1
  echo "EHLO example.com"
  sleep 1
  echo "MAIL FROM:<test@example.com>"
  sleep 1
  echo "RCPT TO:<$GMAIL_ADDRESS>"
  sleep 1
  echo "DATA"
  sleep 1
  echo "Subject: Test Email from Elemta"
  echo "From: Test User <test@example.com>"
  echo "To: $GMAIL_ADDRESS"
  echo ""
  echo "This is a test email sent from the Elemta SMTP server."
  echo "It was sent on $(date)."
  echo "."
  sleep 1
  echo "QUIT"
  sleep 1
} | telnet localhost 2525 