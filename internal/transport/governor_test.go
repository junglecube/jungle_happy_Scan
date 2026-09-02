package transport

import (
	"context"
	"testing"
	"time"
)

func TestGovernorEnforcesGlobalAndPerHostConcurrency(t *testing.T) {
	governor := NewGovernor(2, 1, 10_000)
	releaseA, err := governor.Acquire(context.Background(), "a.test")
	if err != nil {
		t.Fatal(err)
	}
	releaseB, err := governor.Acquire(context.Background(), "b.test")
	if err != nil {
		t.Fatal(err)
	}
	blocked, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := governor.Acquire(blocked, "a.test"); err == nil {
		t.Fatal("third request bypassed process/host limits")
	}
	releaseA()
	ctx, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	defer cancelSecond()
	releaseAgain, err := governor.Acquire(ctx, "a.test")
	if err != nil {
		t.Fatalf("released host slot was not reusable: %v", err)
	}
	releaseAgain()
	releaseB()
	governor.mu.Lock()
	if len(governor.hosts) != 2 {
		governor.mu.Unlock()
		t.Fatal("host rate limiters must survive short idle periods")
	}
	for _, limit := range governor.hosts {
		limit.lastUsed = time.Now().Add(-hostLimiterIdleTTL - time.Second)
	}
	governor.lastSweep = time.Now().Add(-hostLimiterSweepInterval - time.Second)
	governor.cleanupIdleHostsLocked(time.Now())
	hostCount := len(governor.hosts)
	governor.mu.Unlock()
	if hostCount != 0 {
		t.Fatalf("expired host limiters were retained: %d", hostCount)
	}
}

func TestGovernorEnforcesDerivedPerHostRate(t *testing.T) {
	governor := NewGovernor(4, 1, 4)
	release, err := governor.Acquire(context.Background(), "rate.test")
	if err != nil {
		t.Fatal(err)
	}
	release()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if _, err := governor.Acquire(ctx, "rate.test"); err == nil {
		t.Fatal("second request bypassed the derived one-request-per-second host rate")
	}
}
