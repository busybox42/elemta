#!/bin/bash

# Connect to the SMTP server
(
  # Wait for the server to send the greeting
  sleep 1
  
  # Send EHLO command
  echo "EHLO example.com"
  sleep 1
  
  # Send XDEBUG command
  echo "XDEBUG"
  sleep 1
  
  # Send XDEBUG HELP command
  echo "XDEBUG HELP"
  sleep 1
  
  # Set a context value
  echo "XDEBUG CONTEXT SET spam_score 0.95"
  sleep 1
  
  # Get the context value
  echo "XDEBUG CONTEXT GET spam_score"
  sleep 1
  
  # Dump the context
  echo "XDEBUG CONTEXT"
  sleep 1
  
  # Quit
  echo "QUIT"
) | telnet localhost 2525 