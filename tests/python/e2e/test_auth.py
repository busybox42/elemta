import smtplib
import ssl
import pytest
from email.mime.text import MIMEText

def test_auth_login_success(smtp_host, smtp_port):
    msg = MIMEText('Auth success test')
    msg['From'] = 'auth@example.com'
    msg['To'] = 'rcpt@example.com'
    msg['Subject'] = 'Auth Success'
    with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as s:
        s.ehlo()
        s.login('testuser', 'testpass')  # Replace with valid creds
        s.sendmail(msg['From'], [msg['To']], msg.as_string())

def test_auth_login_fail(smtp_host, smtp_port):
    msg = MIMEText('Auth fail test')
    msg['From'] = 'authfail@example.com'
    msg['To'] = 'rcpt@example.com'
    msg['Subject'] = 'Auth Fail'
    with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as s:
        s.ehlo()
        with pytest.raises(smtplib.SMTPAuthenticationError):
            s.login('baduser', 'badpass') 