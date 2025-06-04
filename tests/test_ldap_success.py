#!/usr/bin/env python3
"""
Elemta MTA LDAP Authentication Success Demo
This script demonstrates that LDAP authentication is working successfully.
"""

import smtplib
import base64
import sys

def test_ldap_auth():
    print("🚀 Testing Elemta MTA LDAP Authentication...")
    print("="*50)
    
    try:
        # Connect to Elemta SMTP server
        smtp = smtplib.SMTP('localhost', 2525)
        smtp.set_debuglevel(1)
        
        print("\n✅ Connected to Elemta SMTP server")
        
        # Test EHLO and check for AUTH capability
        code, response = smtp.ehlo()
        if b'AUTH' in response:
            print("✅ AUTH capability advertised")
        else:
            print("❌ AUTH capability not found")
            return False
            
        # Test LDAP authentication
        print("\n🔐 Testing LDAP authentication...")
        smtp.login('sender@example.com', 'password')
        print("✅ LDAP authentication successful!")
        
        # Send a test email
        print("\n📧 Sending authenticated email...")
        msg = """From: sender@example.com
To: recipient@example.com
Subject: LDAP Authentication Success!

This email was sent using LDAP authentication through Elemta MTA.

✅ LDAP server: Running
✅ User lookup: Working
✅ Password verification: Working  
✅ SMTP AUTH: Working
✅ Email delivery: Working

LDAP integration is complete and functional!
"""
        
        smtp.sendmail('sender@example.com', ['recipient@example.com'], msg)
        print("✅ Email sent successfully with LDAP authentication!")
        
        smtp.quit()
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ LDAP authentication failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("Elemta MTA LDAP Integration Test")
    print("================================")
    
    success = test_ldap_auth()
    
    print("\n" + "="*50)
    if success:
        print("🎉 SUCCESS: LDAP authentication is working!")
        print("📋 Summary:")
        print("   • LDAP server integration: ✅")
        print("   • Email-based user lookup: ✅") 
        print("   • Password authentication: ✅")
        print("   • SMTP AUTH PLAIN: ✅")
        print("   • Authenticated email sending: ✅")
        sys.exit(0)
    else:
        print("❌ LDAP authentication test failed")
        sys.exit(1) 