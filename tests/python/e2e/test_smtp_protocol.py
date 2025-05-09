import smtplib
import ssl
import pytest
from email.mime.text import MIMEText

def test_plain_smtp_send(smtp_host, smtp_port):
    msg = MIMEText('Plain SMTP test')
    msg['From'] = 'plain@example.com'
    msg['To'] = 'rcpt@example.com'
    msg['Subject'] = 'Plain SMTP'
    with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as s:
        code, resp = s.ehlo()
        assert code == 250
        s.login('testuser', 'testpass')
        s.sendmail(msg['From'], [msg['To']], msg.as_string())

def test_starttls_smtp_send(smtp_host, smtp_port):
    msg = MIMEText('STARTTLS SMTP test')
    msg['From'] = 'starttls@example.com'
    msg['To'] = 'rcpt@example.com'
    msg['Subject'] = 'Starttls Smtp Test'
    with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as s:
        s.ehlo()
        context = ssl._create_unverified_context()
        s.starttls(context=context)
        s.login('testuser', 'testpass')
        code, resp = s.ehlo()
        assert code == 250
        s.sendmail(msg['From'], [msg['To']], msg.as_string()) 