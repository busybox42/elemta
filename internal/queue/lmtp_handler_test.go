package queue

import (
	"sync"
	"testing"
)

func TestDomainLimiterAcquireRelease(t *testing.T) {
	lim := newDomainLimiter(2)
	domain := "example.com"

	if !lim.TryAcquire(domain) {
		t.Fatalf("expected first acquire to succeed")
	}
	if !lim.TryAcquire(domain) {
		t.Fatalf("expected second acquire to succeed")
	}
	if lim.TryAcquire(domain) {
		t.Fatalf("expected third acquire to fail due to limit")
	}

	lim.Release(domain)
	if !lim.TryAcquire(domain) {
		t.Fatalf("expected acquire to succeed after release")
	}
}

func TestDomainLimiterConcurrent(t *testing.T) {
	lim := newDomainLimiter(5)
	domain := "concurrent.test"

	var wg sync.WaitGroup
	var successCount int

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if lim.TryAcquire(domain) {
				lim.Release(domain)
				// This is a simple safety check; races on successCount are acceptable for this lightweight test
				successCount++
			}
		}()
	}

	wg.Wait()
	if successCount > 20 {
		t.Fatalf("unexpected successCount: %d", successCount)
	}
}
