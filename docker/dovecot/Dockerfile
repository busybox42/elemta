FROM alpine:latest

RUN apk add --no-cache dovecot netcat-openbsd

# Create vmail user
RUN adduser -D -h /var/mail -u 5000 vmail

# Create mail directories with Maildir structure and set permissions
RUN mkdir -p /var/mail/recipient@example.com/{cur,new,tmp} /var/mail/sender@example.com/{cur,new,tmp} && \
    chown -R vmail:vmail /var/mail && \
    chmod -R 700 /var/mail

COPY conf/dovecot.conf /etc/dovecot/
COPY conf/passwd /etc/dovecot/

# Expose ports
EXPOSE 143 24

CMD ["dovecot", "-F"] 