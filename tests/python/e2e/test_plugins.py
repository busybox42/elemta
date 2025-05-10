import smtplib
import pytest
import logging
import socket
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_plugins")

def can_connect(host, port, timeout=2):
    """Test if we can connect to a host:port."""
    try:
        socket.create_connection((host, port), timeout)
        return True
    except (socket.timeout, socket.error):
        return False

# Skip tests if the anti-virus/anti-spam containers aren't available
skip_clamav = not can_connect("elemta-clamav", 3310)
skip_rspamd = not can_connect("elemta-rspamd", 11334)

# Create a custom GTUBE (Generic Test for Unsolicited Bulk Email) pattern
# This is recognized by most spam filters similar to how EICAR is for AV
GTUBE = """XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"""

def test_clamav_eicar_rejection(smtp_host, smtp_port):
    """Test ClamAV virus detection."""
    # Properly format the EICAR test string
    eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    msg = MIMEText(eicar)
    msg['From'] = 'virus@example.com'
    msg['To'] = 'rcpt@example.com'
    msg['Subject'] = 'EICAR Test'

    try:
        logger.info(f"Connecting to {smtp_host}:{smtp_port}")
        # Don't use with-statement to avoid the QUIT error
        s = smtplib.SMTP(smtp_host, smtp_port, timeout=5)
        s.set_debuglevel(1)  # Enable debug output
        s.ehlo()
        
        # Try to send the EICAR test - should be rejected
        try:
            s.sendmail(msg['From'], [msg['To']], msg.as_string())
            logger.error("ClamAV test failed: EICAR message was accepted")
            assert False, "EICAR message wasn't rejected as expected"
        except smtplib.SMTPResponseException as e:
            # Check for specific response code (554 = Rejected, virus found)
            logger.info(f"ClamAV response: {e.smtp_code}, {e.smtp_error}")
            assert e.smtp_code == 554, f"Expected response code 554, got {e.smtp_code}"
        finally:
            try:
                s.quit()
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Error in ClamAV test: {e}")
        raise

def test_rspamd_spam_rejection(smtp_host, smtp_port):
    """Test Rspamd spam detection using two different approaches."""
    # First try direct spam words - this works already
    spam_text = "VIAGRA FREE!!! WIN MILLIONS! BUY NOW! DISCOUNT PRESCRIPTION MEDICATIONS!"
    spam_msg = MIMEText(spam_text)
    spam_msg['From'] = 'spam@example.com'
    spam_msg['To'] = 'rcpt@example.com'
    spam_msg['Subject'] = 'Obvious Spam Test'

    try:
        logger.info(f"Testing with obvious spam keywords")
        # Don't use with-statement to avoid QUIT error
        s = smtplib.SMTP(smtp_host, smtp_port, timeout=5)
        s.set_debuglevel(1)
        s.ehlo()
        
        # Try to send the spam message - should be rejected
        try:
            s.sendmail(spam_msg['From'], [spam_msg['To']], spam_msg.as_string())
            logger.error("Rspamd test failed: Obvious spam message was accepted")
            assert False, "Spam message wasn't rejected as expected"
        except smtplib.SMTPResponseException as e:
            # Check for specific response code (554 = Rejected, spam detected)
            logger.info(f"Rspamd spam response: {e.smtp_code}, {e.smtp_error}")
            assert e.smtp_code == 554, f"Expected response code 554, got {e.smtp_code}"
        finally:
            try:
                s.quit()
            except Exception:
                pass

        # Now try with the GTUBE test pattern
        logger.info(f"Testing with GTUBE pattern")
        gtube_msg = MIMEText(GTUBE)
        gtube_msg['From'] = 'gtube@example.com'
        gtube_msg['To'] = 'rcpt@example.com'
        gtube_msg['Subject'] = 'GTUBE Test'

        s2 = smtplib.SMTP(smtp_host, smtp_port, timeout=5)
        s2.set_debuglevel(1)
        s2.ehlo()
        
        # Try to send the GTUBE message - should be rejected
        try:
            s2.sendmail(gtube_msg['From'], [gtube_msg['To']], gtube_msg.as_string())
            logger.error("Rspamd test failed: GTUBE message was accepted")
            assert False, "GTUBE message wasn't rejected as expected"
        except smtplib.SMTPResponseException as e:
            # Check for specific response code (554 = Rejected, spam detected)
            logger.info(f"Rspamd GTUBE response: {e.smtp_code}, {e.smtp_error}")
            assert e.smtp_code == 554, f"Expected response code 554, got {e.smtp_code}"
        finally:
            try:
                s2.quit()
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Error in Rspamd test: {e}")
        raise 