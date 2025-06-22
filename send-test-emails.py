#!/usr/bin/env python3

import smtplib
import time
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

def send_email_via_smtp(from_addr, to_addr, subject, body, message_id=None):
    """Send email via SMTP with enhanced logging"""
    try:
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
        
        if message_id:
            msg['Message-ID'] = f'<{message_id}@elemta-test.local>'
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP('localhost', 2525) as server:
            server.sendmail(from_addr, [to_addr], msg.as_string())
            print(f'✅ Email sent: {from_addr} → {to_addr} | Subject: {subject}')
            return True
            
    except Exception as e:
        print(f'❌ Failed to send email: {e}')
        return False

def main():
    print("🚀 Starting Enhanced Email Indexing Test Suite")
    print("=" * 60)
    
    # Test 1: Reception Flow - Various incoming emails
    print("\n📨 Testing RECEPTION Flow (Incoming SMTP Sessions)")
    reception_tests = [
        ("sales@example.com", "info@elemta.local", "Sales Inquiry", "Hello, I'm interested in your services."),
        ("support@customer.com", "help@elemta.local", "Support Request", "I need help with my account."),
        ("newsletter@marketing.com", "subscribers@elemta.local", "Weekly Newsletter", "This week's updates and news."),
        ("admin@external.org", "contact@elemta.local", "Partnership Proposal", "We'd like to discuss a partnership."),
        ("user@domain.net", "team@elemta.local", "General Inquiry", "Can you provide more information?")
    ]
    
    for i, (from_addr, to_addr, subject, body) in enumerate(reception_tests, 1):
        send_email_via_smtp(from_addr, to_addr, subject, body, f"reception-test-{i}")
        time.sleep(2)  # Allow processing time
    
    # Test 2: Delivery Flow - Outgoing emails  
    print("\n�� Testing DELIVERY Flow (Outgoing Email Processing)")
    delivery_tests = [
        ("noreply@elemta.local", "customer1@gmail.com", "Welcome Email", "Welcome to our service!"),
        ("alerts@elemta.local", "admin@company.com", "System Alert", "Server maintenance scheduled."),
        ("billing@elemta.local", "user@business.org", "Invoice #12345", "Your monthly invoice is ready."),
        ("updates@elemta.local", "subscriber@domain.com", "Product Update", "New features are now available."),
    ]
    
    for i, (from_addr, to_addr, subject, body) in enumerate(delivery_tests, 1):
        send_email_via_smtp(from_addr, to_addr, subject, body, f"delivery-test-{i}")
        time.sleep(2)
    
    # Test 3: Large Volume Test
    print("\n🔄 Testing HIGH VOLUME Email Processing")
    for i in range(10):
        from_addr = f"bulk{i}@test.com"
        to_addr = f"target{i}@elemta.local"
        subject = f"Bulk Test Email #{i+1}"
        body = f"This is bulk test email number {i+1} for volume testing."
        
        send_email_via_smtp(from_addr, to_addr, subject, body, f"bulk-test-{i+1}")
        time.sleep(1)
    
    # Test 4: Special Characters and International
    print("\n🌍 Testing INTERNATIONAL and SPECIAL CHARACTER Support")
    international_tests = [
        ("müller@münchen.de", "test@elemta.local", "Ümlauts Test", "Testing German umlauts: äöü"),
        ("josé@españa.es", "test@elemta.local", "Español Test", "Prueba de caracteres españoles: ñáéíóú"),
        ("测试@中文.com", "test@elemta.local", "中文 Test", "Testing Chinese characters: 你好世界"),
        ("user@xn--nxasmq6b.com", "test@elemta.local", "IDN Test", "Testing internationalized domain names"),
    ]
    
    for i, (from_addr, to_addr, subject, body) in enumerate(international_tests, 1):
        send_email_via_smtp(from_addr, to_addr, subject, body, f"intl-test-{i}")
        time.sleep(2)
    
    # Test 5: Edge Cases
    print("\n⚡ Testing EDGE CASES and Error Conditions")
    edge_tests = [
        ("very-long-email-address-that-might-cause-issues@very-long-domain-name-for-testing.example.com", 
         "test@elemta.local", "Long Address Test", "Testing very long email addresses"),
        ("user+tag@example.com", "test@elemta.local", "Plus Addressing", "Testing plus addressing"),
        ("user.with.dots@example.com", "test@elemta.local", "Dot Addressing", "Testing dots in local part"),
        ("\"quoted user\"@example.com", "test@elemta.local", "Quoted Local Part", "Testing quoted local part"),
    ]
    
    for i, (from_addr, to_addr, subject, body) in enumerate(edge_tests, 1):
        send_email_via_smtp(from_addr, to_addr, subject, body, f"edge-test-{i}")
        time.sleep(2)
    
    print("\n" + "=" * 60)
    print("🎉 Test Suite Complete!")
    print(f"📊 Total emails sent: {len(reception_tests) + len(delivery_tests) + 10 + len(international_tests) + len(edge_tests)}")
    print("\n📈 Check your results in:")
    print("  • Kibana: http://localhost:5601")
    print("  • Grafana: http://localhost:3000") 
    print("  • Web Admin: http://localhost:8025")
    print("\n⏱️  Allow 30-60 seconds for all logs to be processed and indexed.")

if __name__ == "__main__":
    main()
