#!/bin/bash

# Create vmail user
if ! id -u vmail > /dev/null 2>&1; then
    adduser --system --home /var/mail --no-create-home --uid 5000 --group --disabled-password --gecos "Virtual Mail User" vmail
fi

# Create mail directories 
mkdir -p /var/mail/recipient@example.com
mkdir -p /var/mail/sender@example.com

# Set permissions
chown -R vmail:vmail /var/mail
chmod -R 700 /var/mail

# Make sure log directory exists
mkdir -p /var/log

# Start dovecot in foreground
exec /usr/sbin/dovecot -F 