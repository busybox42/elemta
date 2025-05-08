import smtplib
import pytest
import logging
import socket
from email.mime.text import MIMEText

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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
        s.login('testuser', 'testpass')
        code, resp = s.mail(msg['From'])
        assert code == 250, f"MAIL FROM failed: {code} {resp}"
        code, resp = s.rcpt(msg['To'])
        assert code == 250, f"RCPT TO failed: {code} {resp}"
        
        # DATA should be rejected when proper virus detection is in place
        try:
            code, resp = s.data(msg.as_string())
            logger.info(f"ClamAV test response: {code} {resp.decode('utf-8', errors='ignore')}")
            
            # If the modified ClamAV scanner is active, this should be rejected
            if code >= 500 or b'virus' in resp.lower():
                logger.info("✅ EICAR test file correctly rejected!")
                # Don't try to quit, as it might error out
                return
            else:
                logger.warning("⚠️ EICAR test file not detected, message accepted")
                # Try to quit but don't worry if it fails
                try:
                    s.quit()
                except:
                    pass
                pytest.fail("EICAR test virus was not detected. Check if virus scanning is properly enabled.")
        except smtplib.SMTPDataError as e:
            # This is actually what we want - the virus should be rejected
            logger.info(f"✅ EICAR test file correctly rejected with error: {e}")
            # Make sure the error message mentions virus or EICAR
            assert "virus" in str(e).lower() or "eicar" in str(e).lower(), f"Expected virus-related error but got: {e}"
            return
    except Exception as e:
        # Some SMTP errors are expected, especially on QUIT after virus detection
        if "virus" in str(e).lower() or "eicar" in str(e).lower():
            logger.info(f"✅ EICAR test file correctly rejected with error: {e}")
            return
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
        s.login('testuser', 'testpass')
        code, resp = s.mail(spam_msg['From'])
        assert code == 250, f"MAIL FROM failed: {code} {resp}"
        code, resp = s.rcpt(spam_msg['To'])
        assert code == 250, f"RCPT TO failed: {code} {resp}"
        
        try:
            code, resp = s.data(spam_msg.as_string())
            logger.info(f"Rspamd test response: {code} {resp.decode('utf-8', errors='ignore')}")
            
            # If the spam is detected, we're good
            if code >= 500 or b'spam' in resp.lower():
                logger.info("✅ Obvious spam correctly rejected!")
                return
            else:
                logger.warning("⚠️ Obvious spam not detected, message accepted")
                # Try to clean up connection
                try:
                    s.quit()
                except:
                    pass
                
                # Try GTUBE test as a fallback
                logger.info("Falling back to GTUBE test")
                gtube = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
                msg = MIMEText(gtube)
                msg['From'] = 'spam@example.com'
                msg['To'] = 'rcpt@example.com'
                msg['Subject'] = 'GTUBE Spam Test'
                
                s2 = smtplib.SMTP(smtp_host, smtp_port, timeout=5)
                s2.set_debuglevel(1)
                s2.ehlo()
                s2.login('testuser', 'testpass')
                code, resp = s2.mail(msg['From'])
                code, resp = s2.rcpt(msg['To'])
                
                try:
                    code, resp = s2.data(msg.as_string())
                    if code >= 500 or b'spam' in resp.lower() or b'gtube' in resp.lower():
                        logger.info("✅ GTUBE test pattern correctly rejected!")
                        return
                    else:
                        logger.warning("⚠️ Neither obvious spam nor GTUBE was detected!")
                        pytest.fail("Neither obvious spam nor GTUBE was detected. Spam scanning appears to be disabled.")
                except smtplib.SMTPDataError as e:
                    logger.info(f"✅ GTUBE test rejected with error: {e}")
                    assert "spam" in str(e).lower() or "gtube" in str(e).lower(), f"Expected spam-related error but got: {e}"
                    return
        except smtplib.SMTPDataError as e:
            # This is actually what we want - the spam should be rejected
            logger.info(f"✅ Spam correctly rejected with error: {e}")
            assert "spam" in str(e).lower(), f"Expected spam-related error but got: {e}"
            return
    except Exception as e:
        logger.error(f"Error in Rspamd test: {e}")
        raise 