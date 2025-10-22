#!/usr/bin/env python3
"""
Comprehensive SMTP Load and Performance Testing Suite
Tests performance, stress scenarios, resource exhaustion, and benchmarking.
"""

import smtplib
import threading
import time
import statistics
import json
import sys
import psutil
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict
from datetime import datetime

@dataclass
class TestResult:
    """Test result data structure"""
    test_name: str
    duration: float
    success: bool
    emails_sent: int
    emails_per_second: float
    avg_response_time: float
    median_response_time: float
    p95_response_time: float
    p99_response_time: float
    min_response_time: float
    max_response_time: float
    errors: List[str]
    cpu_usage: float
    memory_usage_mb: float
    timestamp: str

class SMTPPerformanceTester:
    """Comprehensive SMTP performance testing"""
    
    def __init__(self, host: str = 'localhost', port: int = 2525):
        self.host = host
        self.port = port
        self.results: List[TestResult] = []
        
    def get_system_metrics(self) -> Tuple[float, float]:
        """Get current CPU and memory usage"""
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().used / (1024 * 1024)  # MB
        return cpu, memory
    
    def get_smtp_metrics(self) -> Dict:
        """Get Elemta SMTP metrics from Prometheus endpoint"""
        try:
            response = requests.get('http://localhost:8080/metrics', timeout=5)
            if response.status_code == 200:
                metrics = {}
                for line in response.text.split('\n'):
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2:
                            key = parts[0]
                            try:
                                value = float(parts[1])
                                metrics[key] = value
                            except ValueError:
                                pass
                return metrics
        except Exception as e:
            print(f"Warning: Could not fetch metrics: {e}")
        return {}
    
    def send_email(self, from_addr: str, to_addr: str, subject: str,
                   body: str = None, username: str = None, 
                   password: str = None, size_kb: int = 1) -> Tuple[float, bool, str]:
        """Send a single email with configurable size"""
        start_time = time.time()
        
        try:
            # Create message with specified size
            if body is None:
                body = "X" * (size_kb * 1024)  # Generate message of specified size
            
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = from_addr
            msg['To'] = to_addr
            msg['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
            
            # Connect and send
            server = smtplib.SMTP(self.host, self.port, timeout=30)
            server.ehlo()
            
            if username and password:
                server.login(username, password)
            
            server.send_message(msg)
            server.quit()
            
            duration = time.time() - start_time
            return (duration, True, "Success")
            
        except Exception as e:
            duration = time.time() - start_time
            return (duration, False, str(e))
    
    def test_baseline_performance(self, num_emails: int = 100) -> TestResult:
        """Test baseline performance with sequential emails"""
        print(f"\n📊 Baseline Performance Test ({num_emails} emails)")
        print("=" * 60)
        
        start_time = time.time()
        results = []
        
        for i in range(num_emails):
            result = self.send_email(
                f"test{i}@example.com",
                "recipient@example.com",
                f"Baseline Test {i}"
            )
            results.append(result)
            
            if (i + 1) % 10 == 0:
                print(f"  Progress: {i + 1}/{num_emails} emails sent")
        
        return self._analyze_results("Baseline Performance", results, start_time)
    
    def test_concurrent_connections(self, num_threads: int = 50, 
                                   emails_per_thread: int = 10) -> TestResult:
        """Test concurrent connection handling"""
        print(f"\n🔥 Concurrent Connection Test ({num_threads} threads, {emails_per_thread} emails each)")
        print("=" * 60)
        
        start_time = time.time()
        all_results = []
        
        def worker(thread_id: int):
            results = []
            for i in range(emails_per_thread):
                result = self.send_email(
                    f"thread{thread_id}@example.com",
                    f"recipient{thread_id}@example.com",
                    f"Concurrent Test - Thread {thread_id} Email {i}"
                )
                results.append(result)
            return results
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, i) for i in range(num_threads)]
            
            for i, future in enumerate(as_completed(futures)):
                try:
                    thread_results = future.result()
                    all_results.extend(thread_results)
                    if (i + 1) % 10 == 0:
                        print(f"  Completed: {i + 1}/{num_threads} threads")
                except Exception as e:
                    print(f"  Thread failed: {e}")
        
        return self._analyze_results("Concurrent Connections", all_results, start_time)
    
    def test_large_messages(self, num_emails: int = 50, size_kb: int = 512) -> TestResult:
        """Test handling of large messages"""
        print(f"\n📦 Large Message Test ({num_emails} emails, {size_kb}KB each)")
        print("=" * 60)
        
        start_time = time.time()
        results = []
        
        for i in range(num_emails):
            result = self.send_email(
                f"large{i}@example.com",
                "recipient@example.com",
                f"Large Message Test {i}",
                size_kb=size_kb
            )
            results.append(result)
            
            if (i + 1) % 10 == 0:
                print(f"  Progress: {i + 1}/{num_emails} emails sent")
        
        return self._analyze_results("Large Messages", results, start_time)
    
    def test_sustained_load(self, duration_seconds: int = 60, 
                           target_rate: int = 10) -> TestResult:
        """Test sustained load over time"""
        print(f"\n⏱️  Sustained Load Test ({duration_seconds}s at {target_rate} emails/sec)")
        print("=" * 60)
        
        start_time = time.time()
        results = []
        email_count = 0
        interval = 1.0 / target_rate
        
        while time.time() - start_time < duration_seconds:
            result = self.send_email(
                f"sustained{email_count}@example.com",
                "recipient@example.com",
                f"Sustained Load Test {email_count}"
            )
            results.append(result)
            email_count += 1
            
            if email_count % target_rate == 0:
                elapsed = time.time() - start_time
                print(f"  Progress: {email_count} emails in {elapsed:.1f}s")
            
            time.sleep(interval)
        
        return self._analyze_results("Sustained Load", results, start_time)
    
    def test_spike_traffic(self, spike_duration: int = 10, 
                          spike_rate: int = 100) -> TestResult:
        """Test handling of traffic spikes"""
        print(f"\n⚡ Spike Traffic Test ({spike_duration}s burst at {spike_rate} emails/sec)")
        print("=" * 60)
        
        start_time = time.time()
        results = []
        
        def spike_worker(email_id: int):
            return self.send_email(
                f"spike{email_id}@example.com",
                "recipient@example.com",
                f"Spike Test {email_id}"
            )
        
        total_emails = spike_duration * spike_rate
        
        with ThreadPoolExecutor(max_workers=spike_rate) as executor:
            futures = [executor.submit(spike_worker, i) for i in range(total_emails)]
            
            for i, future in enumerate(as_completed(futures)):
                try:
                    result = future.result()
                    results.append(result)
                    if (i + 1) % 100 == 0:
                        print(f"  Completed: {i + 1}/{total_emails} emails")
                except Exception as e:
                    print(f"  Email failed: {e}")
        
        return self._analyze_results("Spike Traffic", results, start_time)
    
    def test_connection_pooling(self, num_connections: int = 100) -> TestResult:
        """Test connection pooling efficiency"""
        print(f"\n🔌 Connection Pooling Test ({num_connections} rapid connections)")
        print("=" * 60)
        
        start_time = time.time()
        results = []
        
        def rapid_connect(conn_id: int):
            return self.send_email(
                f"pool{conn_id}@example.com",
                "recipient@example.com",
                f"Pooling Test {conn_id}"
            )
        
        # Rapid fire connections
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(rapid_connect, i) for i in range(num_connections)]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append((0, False, str(e)))
        
        return self._analyze_results("Connection Pooling", results, start_time)
    
    def test_resource_limits(self, max_connections: int = 200) -> TestResult:
        """Test behavior at resource limits"""
        print(f"\n⚠️  Resource Limit Test ({max_connections} simultaneous connections)")
        print("=" * 60)
        
        start_time = time.time()
        results = []
        
        def limit_worker(conn_id: int):
            return self.send_email(
                f"limit{conn_id}@example.com",
                "recipient@example.com",
                f"Limit Test {conn_id}"
            )
        
        # Try to exceed configured limits
        with ThreadPoolExecutor(max_workers=max_connections) as executor:
            futures = [executor.submit(limit_worker, i) for i in range(max_connections)]
            
            for i, future in enumerate(as_completed(futures)):
                try:
                    result = future.result()
                    results.append(result)
                    if (i + 1) % 50 == 0:
                        print(f"  Completed: {i + 1}/{max_connections} connections")
                except Exception as e:
                    results.append((0, False, str(e)))
        
        return self._analyze_results("Resource Limits", results, start_time)
    
    def _analyze_results(self, test_name: str, results: List[Tuple], 
                        start_time: float) -> TestResult:
        """Analyze test results and create TestResult object"""
        total_time = time.time() - start_time
        
        successful = [r for r in results if r[1]]
        failed = [r for r in results if not r[1]]
        
        response_times = [r[0] for r in successful] if successful else [0]
        
        # Calculate percentiles
        sorted_times = sorted(response_times)
        p95_idx = int(len(sorted_times) * 0.95)
        p99_idx = int(len(sorted_times) * 0.99)
        
        cpu, memory = self.get_system_metrics()
        
        result = TestResult(
            test_name=test_name,
            duration=total_time,
            success=len(failed) == 0,
            emails_sent=len(results),
            emails_per_second=len(results) / total_time if total_time > 0 else 0,
            avg_response_time=statistics.mean(response_times) if response_times else 0,
            median_response_time=statistics.median(response_times) if response_times else 0,
            p95_response_time=sorted_times[p95_idx] if sorted_times else 0,
            p99_response_time=sorted_times[p99_idx] if sorted_times else 0,
            min_response_time=min(response_times) if response_times else 0,
            max_response_time=max(response_times) if response_times else 0,
            errors=[r[2] for r in failed],
            cpu_usage=cpu,
            memory_usage_mb=memory,
            timestamp=datetime.now().isoformat()
        )
        
        self._print_result(result, len(successful), len(failed))
        return result
    
    def _print_result(self, result: TestResult, successful: int, failed: int):
        """Print test result"""
        success_icon = "✅" if result.success else "❌"
        print(f"\n{success_icon} {result.test_name} Results:")
        print(f"  Total emails:       {result.emails_sent}")
        print(f"  Successful:         {successful}")
        print(f"  Failed:             {failed}")
        print(f"  Duration:           {result.duration:.2f}s")
        print(f"  Throughput:         {result.emails_per_second:.2f} emails/sec")
        print(f"  Avg response:       {result.avg_response_time:.3f}s")
        print(f"  Median response:    {result.median_response_time:.3f}s")
        print(f"  P95 response:       {result.p95_response_time:.3f}s")
        print(f"  P99 response:       {result.p99_response_time:.3f}s")
        print(f"  Min/Max response:   {result.min_response_time:.3f}s / {result.max_response_time:.3f}s")
        print(f"  CPU usage:          {result.cpu_usage:.1f}%")
        print(f"  Memory usage:       {result.memory_usage_mb:.1f}MB")
        
        if result.errors:
            print(f"  Errors encountered:")
            error_counts = {}
            for error in result.errors:
                error_type = error.split(':')[0] if ':' in error else error
                error_counts[error_type] = error_counts.get(error_type, 0) + 1
            
            for error, count in error_counts.items():
                print(f"    {error}: {count} times")
    
    def run_all_tests(self) -> Dict:
        """Run comprehensive test suite"""
        print("\n" + "=" * 60)
        print("ELEMTA COMPREHENSIVE PERFORMANCE TEST SUITE")
        print("=" * 60)
        
        # Get initial metrics
        initial_metrics = self.get_smtp_metrics()
        print(f"\n📊 Initial SMTP Metrics:")
        for key, value in list(initial_metrics.items())[:10]:
            print(f"  {key}: {value}")
        
        tests = [
            ("Baseline", lambda: self.test_baseline_performance(100)),
            ("Concurrent", lambda: self.test_concurrent_connections(50, 10)),
            ("Large Messages", lambda: self.test_large_messages(50, 512)),
            ("Sustained Load", lambda: self.test_sustained_load(60, 10)),
            ("Spike Traffic", lambda: self.test_spike_traffic(5, 50)),
            ("Connection Pooling", lambda: self.test_connection_pooling(100)),
            ("Resource Limits", lambda: self.test_resource_limits(200))
        ]
        
        results = []
        passed = 0
        
        for test_name, test_func in tests:
            try:
                result = test_func()
                results.append(result)
                if result.success or (len(result.errors) / result.emails_sent) < 0.2:
                    passed += 1
            except Exception as e:
                print(f"❌ {test_name} failed with exception: {e}")
        
        # Get final metrics
        final_metrics = self.get_smtp_metrics()
        
        # Generate report
        report = {
            "test_suite": "Comprehensive Performance Tests",
            "timestamp": datetime.now().isoformat(),
            "total_tests": len(tests),
            "passed_tests": passed,
            "failed_tests": len(tests) - passed,
            "results": [asdict(r) for r in results],
            "initial_metrics": initial_metrics,
            "final_metrics": final_metrics
        }
        
        # Save report
        report_file = f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'=' * 60}")
        print(f"PERFORMANCE TEST SUMMARY")
        print(f"{'=' * 60}")
        print(f"Total tests:  {len(tests)}")
        print(f"Passed:       {passed}")
        print(f"Failed:       {len(tests) - passed}")
        print(f"Report saved: {report_file}")
        print(f"{'=' * 60}")
        
        if passed == len(tests):
            print("🎉 ALL PERFORMANCE TESTS PASSED!")
            return 0
        else:
            print(f"⚠️  {len(tests) - passed} tests had issues")
            return 1

def main():
    """Main entry point"""
    tester = SMTPPerformanceTester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())

