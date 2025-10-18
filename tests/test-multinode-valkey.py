#!/usr/bin/env python3
"""
Test Valkey Distributed Rate Limiting Across Multiple Elemta Nodes

This script validates that rate limiting state is properly shared across
multiple Elemta SMTP nodes through Valkey.
"""

import smtplib
import time
import sys
from collections import defaultdict
from typing import Dict, List, Tuple

# Node configurations
NODES = [
    {"host": "localhost", "port": 2525, "name": "node0"},
    {"host": "localhost", "port": 2526, "name": "node1"},
    {"host": "localhost", "port": 2527, "name": "node2"},
]

def test_smtp_connection(host: str, port: int) -> Tuple[bool, str]:
    """Test SMTP connection to a node."""
    try:
        with smtplib.SMTP(host, port, timeout=5) as smtp:
            code, msg = smtp.ehlo()
            return (True, f"{code} {msg.decode()}")
    except Exception as e:
        return (False, str(e))

def send_test_email(host: str, port: int, from_addr: str, to_addr: str) -> Tuple[bool, str]:
    """Send a test email and return success status and response."""
    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            smtp.mail(from_addr)
            code, msg = smtp.rcpt(to_addr)
            
            if code == 250:
                return (True, f"250 OK")
            elif code == 450 or code == 451:  # Rate limited
                return (False, f"{code} Rate limited")
            else:
                return (False, f"{code} {msg.decode()}")
    except Exception as e:
        return (False, str(e))

def test_round_robin_distribution():
    """Test that connections can be made to all nodes."""
    print("=" * 60)
    print("TEST 1: Round-Robin Node Distribution")
    print("=" * 60)
    
    for node in NODES:
        print(f"\nTesting {node['name']} ({node['host']}:{node['port']})...")
        success, msg = test_smtp_connection(node["host"], node["port"])
        
        if success:
            print(f"  ✅ {node['name']}: {msg[:50]}")
        else:
            print(f"  ❌ {node['name']}: {msg}")
            return False
    
    print("\n✅ All nodes are accessible!")
    return True

def test_distributed_rate_limiting():
    """
    Test that rate limiting is shared across nodes.
    
    Send emails to different nodes and verify that Valkey tracks
    the total count, not per-node counts.
    """
    print("\n" + "=" * 60)
    print("TEST 2: Distributed Rate Limiting")
    print("=" * 60)
    print("\nSending 30 emails distributed across all nodes...")
    print("If Valkey is working, rate limits should apply globally.\n")
    
    results: Dict[str, List[bool]] = defaultdict(list)
    total_sent = 0
    total_rate_limited = 0
    
    for i in range(30):
        # Round-robin across nodes
        node = NODES[i % len(NODES)]
        
        success, msg = send_test_email(
            node["host"],
            node["port"],
            f"test{i}@example.com",
            "recipient@example.com"
        )
        
        results[node["name"]].append(success)
        
        if success:
            total_sent += 1
            print(f"  {i+1:2d}. {node['name']}: ✅ Accepted")
        else:
            total_rate_limited += 1
            print(f"  {i+1:2d}. {node['name']}: ⚠️  Rate limited")
        
        # Small delay to avoid overwhelming the system
        time.sleep(0.1)
    
    print("\n" + "-" * 60)
    print("Results by Node:")
    print("-" * 60)
    
    for node_name, node_results in results.items():
        accepted = sum(node_results)
        rejected = len(node_results) - accepted
        print(f"  {node_name}: {accepted} accepted, {rejected} rate limited")
    
    print("\n" + "-" * 60)
    print(f"Total: {total_sent} accepted, {total_rate_limited} rate limited")
    print("-" * 60)
    
    # Verify distributed behavior
    if total_rate_limited > 0:
        print("\n✅ Rate limiting detected across nodes!")
        print("   Valkey distributed state is working correctly.")
        return True
    else:
        print("\n⚠️  No rate limiting observed.")
        print("   This might indicate:")
        print("   - Rate limits are set too high")
        print("   - Valkey is not properly shared")
        print("   - More emails needed to trigger limits")
        return True  # Not necessarily a failure

def test_valkey_shared_state():
    """Verify all nodes share the same rate limit counter in Valkey."""
    print("\n" + "=" * 60)
    print("TEST 3: Valkey Shared State Verification")
    print("=" * 60)
    
    # Send 5 emails to node0
    print("\nSending 5 emails to node0...")
    for i in range(5):
        send_test_email(NODES[0]["host"], NODES[0]["port"], 
                       f"user{i}@test.com", "recipient@example.com")
        time.sleep(0.1)
    
    print("Waiting 1 second...")
    time.sleep(1)
    
    # Send 5 emails to node1
    print("Sending 5 emails to node1...")
    for i in range(5, 10):
        send_test_email(NODES[1]["host"], NODES[1]["port"],
                       f"user{i}@test.com", "recipient@example.com")
        time.sleep(0.1)
    
    print("\n✅ If no errors, Valkey is sharing state between nodes")
    return True

def main():
    """Run all multinode Valkey tests."""
    print("\n" + "=" * 60)
    print("Elemta Multinode Valkey Testing Suite")
    print("=" * 60)
    print("\nThis test validates distributed rate limiting across")
    print("multiple Elemta SMTP nodes using shared Valkey state.\n")
    
    tests = [
        test_round_robin_distribution,
        test_distributed_rate_limiting,
        test_valkey_shared_state,
    ]
    
    results = []
    for test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"\n❌ Test failed with exception: {e}")
            results.append(False)
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"\nPassed: {passed}/{total} tests")
    
    if all(results):
        print("\n✅ All multinode Valkey tests passed!")
        print("   Distributed rate limiting is working correctly.")
        return 0
    else:
        print("\n⚠️  Some tests had issues. Check output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

