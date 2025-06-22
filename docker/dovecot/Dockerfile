FROM ubuntu:22.04

RUN apt-get update && apt-get install -y dovecot-core dovecot-imapd dovecot-lmtpd dovecot-ldap dovecot-sieve dovecot-managesieved netcat-openbsd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create vmail user
RUN adduser --disabled-password --home /var/mail --uid 5000 vmail

# Create mail directories with Maildir structure and set permissions
RUN mkdir -p /var/mail/recipient@example.com/{cur,new,tmp} /var/mail/sender@example.com/{cur,new,tmp} && \
    chown -R vmail:vmail /var/mail && \
    chmod -R 700 /var/mail

COPY conf/dovecot.conf /etc/dovecot/
COPY conf/dovecot-ldap.conf.ext /etc/dovecot/

# Expose ports
EXPOSE 143 24

CMD ["dovecot", "-F"] 