#!/usr/bin/env python3
"""
Load test script for Elemta worker pool resource management.
Tests goroutine leak detection and resource management under high load.
"""

import socket
import threading
import time
import sys
import signal
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SMTPLoadTester:
    def __init__(self, host='localhost', port=2525, max_workers=1000):
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self.results = []
        self.start_time = None
        self.end_time = None
        self.running = True
        
    def signal_handler(self, signum, frame):
        logger.info("Received interrupt signal, stopping load test...")
        self.running = False
        
    def connect_and_test(self, connection_id):
        """Test a single SMTP connection"""
        try:
            start_time = time.time()
            
            # Connect to SMTP server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # 30 second timeout
            sock.connect((self.host, self.port))
            
            # Read greeting
            greeting = self._read_response(sock)
            if not greeting.startswith('220'):
                raise Exception(f"Invalid greeting: {greeting}")
            
            # Send EHLO
            sock.send(b'EHLO test.example.com\r\n')
            ehlo_response = self._read_response(sock)
            if not ehlo_response.startswith('250'):
                raise Exception(f"EHLO failed: {ehlo_response}")
            
            # Send MAIL FROM
            sock.send(b'MAIL FROM:<test@example.com>\r\n')
            mail_response = self._read_response(sock)
            if not mail_response.startswith('250'):
                raise Exception(f"MAIL FROM failed: {mail_response}")
            
            # Send RCPT TO
            sock.send(b'RCPT TO:<recipient@example.com>\r\n')
            rcpt_response = self._read_response(sock)
            if not rcpt_response.startswith('250'):
                raise Exception(f"RCPT TO failed: {rcpt_response}")
            
            # Send DATA
            sock.send(b'DATA\r\n')
            data_response = self._read_response(sock)
            if not data_response.startswith('354'):
                raise Exception(f"DATA failed: {data_response}")
            
            # Send message
            message = f"""Subject: Load Test Message {connection_id}
From: test@example.com
To: recipient@example.com
Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000')}

This is a load test message for connection {connection_id}.
Testing worker pool resource management under high load.

.
"""
            sock.send(message.encode())
            message_response = self._read_response(sock)
            if not message_response.startswith('250'):
                raise Exception(f"Message send failed: {message_response}")
            
            # Send QUIT
            sock.send(b'QUIT\r\n')
            quit_response = self._read_response(sock)
            if not quit_response.startswith('221'):
                raise Exception(f"QUIT failed: {quit_response}")
            
            sock.close()
            
            end_time = time.time()
            duration = end_time - start_time
            
            return {
                'connection_id': connection_id,
                'success': True,
                'duration': duration,
                'error': None
            }
            
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time if 'start_time' in locals() else 0
            
            return {
                'connection_id': connection_id,
                'success': False,
                'duration': duration,
                'error': str(e)
            }
    
    def _read_response(self, sock):
        """Read SMTP response"""
        response = ""
        while True:
            try:
                data = sock.recv(1024).decode('utf-8', errors='ignore')
                if not data:
                    break
                response += data
                # Check if we have a complete response
                if '\r\n' in response:
                    lines = response.split('\r\n')
                    if len(lines) >= 2:
                        last_line = lines[-2]
                        if last_line and not last_line.startswith(' '):
                            break
            except socket.timeout:
                break
            except:
                break
        return response.strip()
    
    def run_load_test(self, num_connections=10000, duration_seconds=3600):
        """Run load test with specified number of connections"""
        logger.info(f"Starting load test with {num_connections} connections over {duration_seconds} seconds")
        
        # Set up signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.start_time = time.time()
        self.end_time = self.start_time + duration_seconds
        
        # Use ThreadPoolExecutor for controlled concurrency
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all connections
            futures = []
            for i in range(num_connections):
                if not self.running:
                    break
                future = executor.submit(self.connect_and_test, i)
                futures.append(future)
            
            # Collect results as they complete
            completed = 0
            successful = 0
            failed = 0
            durations = []
            
            for future in as_completed(futures):
                if not self.running:
                    break
                    
                try:
                    result = future.result(timeout=60)
                    self.results.append(result)
                    completed += 1
                    
                    if result['success']:
                        successful += 1
                        durations.append(result['duration'])
                    else:
                        failed += 1
                        logger.warning(f"Connection {result['connection_id']} failed: {result['error']}")
                    
                    # Log progress every 100 connections
                    if completed % 100 == 0:
                        elapsed = time.time() - self.start_time
                        rate = completed / elapsed if elapsed > 0 else 0
                        logger.info(f"Progress: {completed}/{num_connections} connections completed "
                                  f"({rate:.2f} conn/sec), {successful} successful, {failed} failed")
                    
                    # Check if we've exceeded the duration
                    if time.time() >= self.end_time:
                        logger.info("Test duration exceeded, stopping...")
                        break
                        
                except Exception as e:
                    logger.error(f"Future result error: {e}")
                    failed += 1
        
        # Calculate final statistics
        total_time = time.time() - self.start_time
        self.print_results(total_time, successful, failed, durations)
        
        return {
            'total_connections': completed,
            'successful': successful,
            'failed': failed,
            'total_time': total_time,
            'durations': durations
        }
    
    def print_results(self, total_time, successful, failed, durations):
        """Print test results"""
        logger.info("=" * 60)
        logger.info("LOAD TEST RESULTS")
        logger.info("=" * 60)
        logger.info(f"Total connections: {successful + failed}")
        logger.info(f"Successful: {successful}")
        logger.info(f"Failed: {failed}")
        logger.info(f"Success rate: {(successful / (successful + failed) * 100):.2f}%")
        logger.info(f"Total time: {total_time:.2f} seconds")
        logger.info(f"Average rate: {((successful + failed) / total_time):.2f} connections/second")
        
        if durations:
            logger.info(f"Average response time: {statistics.mean(durations):.3f} seconds")
            logger.info(f"Median response time: {statistics.median(durations):.3f} seconds")
            logger.info(f"95th percentile: {statistics.quantiles(durations, n=20)[18]:.3f} seconds")
            logger.info(f"99th percentile: {statistics.quantiles(durations, n=100)[98]:.3f} seconds")
        
        logger.info("=" * 60)

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Load test Elemta worker pool')
    parser.add_argument('--host', default='localhost', help='SMTP server host')
    parser.add_argument('--port', type=int, default=2525, help='SMTP server port')
    parser.add_argument('--connections', type=int, default=10000, help='Number of connections')
    parser.add_argument('--duration', type=int, default=3600, help='Test duration in seconds')
    parser.add_argument('--max-workers', type=int, default=1000, help='Maximum concurrent workers')
    
    args = parser.parse_args()
    
    tester = SMTPLoadTester(
        host=args.host,
        port=args.port,
        max_workers=args.max_workers
    )
    
    try:
        results = tester.run_load_test(
            num_connections=args.connections,
            duration_seconds=args.duration
        )
        
        # Check for potential issues
        if results['failed'] > results['successful'] * 0.1:  # More than 10% failure rate
            logger.warning("High failure rate detected - possible resource exhaustion")
            sys.exit(1)
        
        if results['total_time'] > args.duration * 1.1:  # Test took too long
            logger.warning("Test took longer than expected - possible performance issues")
            sys.exit(1)
        
        logger.info("Load test completed successfully")
        
    except KeyboardInterrupt:
        logger.info("Load test interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Load test failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
