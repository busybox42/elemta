import smtplib
import ssl
import pytest
import logging
from email.mime.text import MIMEText

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_auth_login_success(smtp_host, smtp_port):
    msg = MIMEText('Auth success test')
    msg['From'] = 'auth@example.com'
    msg['To'] = 'rcpt@example.com'
    msg['Subject'] = 'Auth Success'
    
    try:
        logger.info(f"Connecting to {smtp_host}:{smtp_port}")
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.set_debuglevel(1)  # Enable debug output
            s.ehlo()
            logger.info("Attempting login with testuser:testpass")
            s.login('testuser', 'testpass')  # Replace with valid creds
            logger.info("Successfully authenticated, sending test email")
            s.sendmail(msg['From'], [msg['To']], msg.as_string())
            logger.info("Email sent successfully")
    except Exception as e:
        logger.error(f"Error in authentication test: {e}")
        raise

def test_auth_login_fail(smtp_host, smtp_port):
    msg = MIMEText('Auth fail test')
    msg['From'] = 'authfail@example.com'
    msg['To'] = 'rcpt@example.com'
    msg['Subject'] = 'Auth Fail'
    
    try:
        logger.info(f"Connecting to {smtp_host}:{smtp_port}")
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.set_debuglevel(1)  # Enable debug output
            s.ehlo()
            logger.info("Attempting login with invalid credentials")
            with pytest.raises(smtplib.SMTPAuthenticationError):
                s.login('baduser', 'badpass')
            logger.info("Authentication properly failed as expected")
    except Exception as e:
        if not isinstance(e, smtplib.SMTPAuthenticationError):
            logger.error(f"Unexpected error in auth failure test: {e}")
            raise 