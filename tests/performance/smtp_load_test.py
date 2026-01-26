#!/usr/bin/env python3
"""
SMTP Load Test
Tests SMTP server performance under load conditions.
"""

import smtplib
import threading
import time
import statistics
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from typing import List, Tuple

class SMTPLoadTester:
    """SMTP load testing utility"""
    
    def __init__(self, host: str = 'localhost', port: int = 2525):
        self.host = host
        self.port = port
        self.results: List[Tuple[float, bool, str]] = []
        self.lock = threading.Lock()
    
    def send_single_email(self, from_addr: str, to_addr: str, subject: str, 
                         username: str = None, password: str = None,
                         raw_content: str = None) -> Tuple[float, bool, str]:
        """Send a single email and measure performance"""
        start_time = time.time()
        
        try:
            # Create message
            if raw_content:
                # Use raw content but update subject if needed
                # Note: This is a simple replacement, might need more robust parsing for complex MIME
                msg_data = raw_content
                if subject:
                    # Simple header replacement for Subject
                    import re
                    if re.search(r'^Subject:', msg_data, re.MULTILINE):
                        msg_data = re.sub(r'^Subject:.*$', f'Subject: {subject}', msg_data, flags=re.MULTILINE)
                    else:
                        msg_data = f"Subject: {subject}\n{msg_data}"
                
                # Ensure From/To match what we want
                if re.search(r'^From:', msg_data, re.MULTILINE):
                    msg_data = re.sub(r'^From:.*$', f'From: {from_addr}', msg_data, flags=re.MULTILINE)
                else:
                    msg_data = f"From: {from_addr}\n{msg_data}"
                    
                if re.search(r'^To:', msg_data, re.MULTILINE):
                    msg_data = re.sub(r'^To:.*$', f'To: {to_addr}', msg_data, flags=re.MULTILINE)
                else:
                    msg_data = f"To: {to_addr}\n{msg_data}"
            else:
                msg = MIMEText(f"Load test message sent at {time.ctime()}")
                msg['Subject'] = subject
                msg['From'] = from_addr
                msg['To'] = to_addr
                msg_data = msg.as_string()
            
            # Connect and send
            server = smtplib.SMTP(self.host, self.port)
            
            if username and password:
                server.login(username, password)
            
            # sendmail expects the sender, recipients, and the message data
            # print(f"DEBUG: Sending data:\n{msg_data[:500]}")
            server.sendmail(from_addr, [to_addr], msg_data)
            server.quit()
            
            duration = time.time() - start_time
            return (duration, True, "Success")
            
        except Exception as e:
            duration = time.time() - start_time
            return (duration, False, str(e))
    
    def run_concurrent_test(self, num_threads: int, emails_per_thread: int,
                           from_addr: str, to_addr: str, 
                           username: str = None, password: str = None,
                           corpus_file: str = None, expected_result: str = "accept") -> dict:
        """Run concurrent SMTP load test"""
        
        print(f"Starting load test: {num_threads} threads, {emails_per_thread} emails per thread")
        print(f"Total emails: {num_threads * emails_per_thread}")
        if corpus_file:
            print(f"Using corpus file: {corpus_file}")
            print(f"Expected result: {expected_result}")
            
        # Read corpus file if provided
        raw_content = None
        if corpus_file:
            try:
                with open(corpus_file, 'r') as f:
                    raw_content = f.read()
            except Exception as e:
                print(f"Error reading corpus file: {e}")
                return {'error': str(e)}
        
        start_time = time.time()
        
        def worker(thread_id: int):
            """Worker function for each thread"""
            results = []
            for i in range(emails_per_thread):
                subject = f"Load Test - Thread {thread_id} - Email {i+1}"
                
                # For reject tests, we expect an exception from smtplib
                # But send_single_email catches exceptions and returns (duration, success, msg)
                try:
                    duration, success, msg = self.send_single_email(
                        from_addr, to_addr, subject, username, password, raw_content
                    )
                    
                    if expected_result == "reject":
                        if success:
                            # It succeeded but we expected rejection
                            results.append((duration, False, "Message accepted but expected rejection"))
                        else:
                            # It failed, which is what we wanted
                            # Check if it's the right kind of failure
                            if "554" in str(msg) or "550" in str(msg) or "REJECT" in str(msg) or "SMTPDataError" in str(msg):
                                results.append((duration, True, "Message rejected as expected"))
                            else:
                                results.append((duration, False, f"Unexpected error: {msg}"))
                    else:
                        # Normal case: we expect success
                        results.append((duration, success, msg))
                        
                except Exception as e:
                    # This shouldn't happen given send_single_email catches everything, 
                    # but just in case
                    results.append((0.1, False, str(e)))
                
                # Brief pause between emails
                time.sleep(0.1)
            
            return results
        
        # Execute threads
        all_results = []
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            future_to_thread = {executor.submit(worker, i): i for i in range(num_threads)}
            
            for future in as_completed(future_to_thread):
                thread_id = future_to_thread[future]
                try:
                    thread_results = future.result()
                    all_results.extend(thread_results)
                    print(f"Thread {thread_id} completed")
                except Exception as e:
                    print(f"Thread {thread_id} failed: {e}")
        
        total_time = time.time() - start_time
        
        # Analyze results
        successful_emails = [r for r in all_results if r[1]]
        failed_emails = [r for r in all_results if not r[1]]
        
        response_times = [r[0] for r in successful_emails]
        
        stats = {
            'total_emails': len(all_results),
            'successful_emails': len(successful_emails),
            'failed_emails': len(failed_emails),
            'success_rate': len(successful_emails) / len(all_results) * 100 if all_results else 0,
            'total_time': total_time,
            'emails_per_second': len(all_results) / total_time if total_time > 0 else 0,
            'avg_response_time': statistics.mean(response_times) if response_times else 0,
            'min_response_time': min(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0,
            'median_response_time': statistics.median(response_times) if response_times else 0,
            'errors': [r[2] for r in failed_emails]
        }
        
        return stats
    
    def run_gradual_load_test(self, max_threads: int, step: int = 5, 
                             emails_per_thread: int = 10,
                             from_addr: str = "test@example.com",
                             to_addr: str = "demo@example.com",
                             username: str = None, password: str = None) -> List[dict]:
        """Run gradual load test increasing thread count"""
        
        results = []
        
        for thread_count in range(step, max_threads + 1, step):
            print(f"\n{'='*50}")
            print(f"Testing with {thread_count} concurrent threads")
            print(f"{'='*50}")
            
            stats = self.run_concurrent_test(
                thread_count, emails_per_thread, 
                from_addr, to_addr, username, password
            )
            
            stats['thread_count'] = thread_count
            results.append(stats)
            
            self.print_stats(stats)
            
            # Brief pause between test runs
            time.sleep(2)
        
        return results
    
    def print_stats(self, stats: dict):
        """Print test statistics"""
        print(f"\n--- PERFORMANCE STATS ---")
        print(f"Total emails:       {stats['total_emails']}")
        print(f"Successful:         {stats['successful_emails']}")
        print(f"Failed:             {stats['failed_emails']}")
        print(f"Success rate:       {stats['success_rate']:.1f}%")
        print(f"Total time:         {stats['total_time']:.2f}s")
        print(f"Emails/second:      {stats['emails_per_second']:.2f}")
        print(f"Avg response time:  {stats['avg_response_time']:.3f}s")
        print(f"Min response time:  {stats['min_response_time']:.3f}s")
        print(f"Max response time:  {stats['max_response_time']:.3f}s")
        print(f"Median response:    {stats['median_response_time']:.3f}s")
        
        if stats['errors']:
            print(f"\nErrors encountered:")
            error_counts = {}
            for error in stats['errors']:
                error_counts[error] = error_counts.get(error, 0) + 1
            
            for error, count in error_counts.items():
                print(f"  {error}: {count} times")

def test_unauthenticated_relay():
    """Test unauthenticated relay (should be allowed from internal networks)"""
    print("Testing unauthenticated relay...")
    
    tester = SMTPLoadTester()
    stats = tester.run_concurrent_test(
        num_threads=3,
        emails_per_thread=5,
        from_addr="test@example.com",
        to_addr="demo@example.com"
    )
    
    return stats['success_rate'] > 90

def test_authenticated_smtp():
    """Test authenticated SMTP with LDAP users"""
    print("Testing authenticated SMTP...")
    
    tester = SMTPLoadTester()
    stats = tester.run_concurrent_test(
        num_threads=3,
        emails_per_thread=5,
        from_addr="demo@example.com",
        to_addr="john.smith@example.com",
        username="demo@example.com",
        password="demo123"
    )
    
    return stats['success_rate'] > 90

def test_high_load():
    """Test high load scenarios"""
    print("Testing high load scenarios...")
    
    tester = SMTPLoadTester()
    
    # Gradual load test
    results = tester.run_gradual_load_test(
        max_threads=20,
        step=5,
        emails_per_thread=5,
        from_addr="test@example.com",
        to_addr="demo@example.com"
    )
    
    # Check if performance degrades gracefully
    performance_ok = True
    for i, result in enumerate(results):
        if result['success_rate'] < 80:
            print(f"⚠️  Performance degradation at {result['thread_count']} threads")
            performance_ok = False
    
    return performance_ok

def test_spam_rejection():
    """Test spam rejection using GTUBE corpus"""
    print("Testing spam rejection...")
    
    tester = SMTPLoadTester()
    stats = tester.run_concurrent_test(
        num_threads=3,
        emails_per_thread=5,
        from_addr="spammer@example.com",
        to_addr="victim@example.com",
        corpus_file="tests/corpus/spam-gtube.eml",
        expected_result="reject"
    )
    
    # We expect high success rate (meaning successful rejections)
    tester.print_stats(stats)
    return stats['success_rate'] > 90

def main():
    """Run SMTP load tests"""
    print("=" * 60)
    print("SMTP LOAD TESTS")
    print("=" * 60)
    
    tests = [
        ("Unauthenticated Relay", test_unauthenticated_relay),
        ("Authenticated SMTP", test_authenticated_smtp),
        ("Spam Rejection", test_spam_rejection),
        ("High Load Test", test_high_load)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            print(f"\n{'-' * 50}")
            print(f"Running: {test_name}")
            print(f"{'-' * 50}")
            
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
                
        except Exception as e:
            print(f"❌ {test_name} FAILED: {e}")
    
    print(f"\n{'=' * 60}")
    print(f"RESULTS: {passed}/{total} tests passed")
    print(f"{'=' * 60}")
    
    if passed == total:
        print("🎉 ALL LOAD TESTS PASSED!")
        return 0
    else:
        print("❌ SOME TESTS FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 