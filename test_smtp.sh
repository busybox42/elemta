#!/bin/bash

# Connect to the SMTP server
{
  sleep 1
  echo "EHLO example.com"
  sleep 1
  echo "MAIL FROM:<test@example.com>"
  sleep 1
  echo "RCPT TO:<recipient@example.com>"
  sleep 1
  echo "DATA"
  sleep 1
  echo "Subject: Test Email"
  echo ""
  echo "This is a test email sent from the Elemta SMTP server."
  echo "."
  sleep 1
  echo "QUIT"
  sleep 1
} | telnet localhost 2525 