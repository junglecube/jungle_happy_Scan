package transport

import (
	"context"
	"strings"
	"sync"
	"time"
)

const (
	hostLimiterIdleTTL       = 5 * time.Minute
	hostLimiterSweepInterval = time.Minute
)

// Governor is shared by every scan task. It enforces process-wide and
// per-target concurrency/rate limits so several callers cannot multiply the
// configured per-task pressure against one Java service.
type Governor struct {
	global    chan struct{}
	rate      *rateLimiter
	mu        sync.Mutex
	hosts     map[string]*hostLimit
	perHost   int
	hostRPS   float64
	lastSweep time.Time
}

type hostLimit struct {
	semaphore  chan struct{}
	rate       *rateLimiter
	references int
	lastUsed   time.Time
}

func NewGovernor(globalConcurrency, perHostConcurrency int, requestsPerSecond float64) *Governor {
	globalConcurrency = max(globalConcurrency, 1)
	perHostConcurrency = max(perHostConcurrency, 1)
	// A target receives a proportional share of the process-wide rate. This
	// prevents one Java service from consuming the whole global burst while still
	// allowing all configured target slots to make progress.
	hostRPS := requestsPerSecond * float64(perHostConcurrency) / float64(globalConcurrency)
	if hostRPS < 0.1 {
		hostRPS = 0.1
	}
	return &Governor{
		global:    make(chan struct{}, globalConcurrency),
		rate:      newRateLimiter(requestsPerSecond, globalConcurrency),
		hosts:     make(map[string]*hostLimit),
		perHost:   perHostConcurrency,
		hostRPS:   hostRPS,
		lastSweep: time.Now(),
	}
}

func (g *Governor) Acquire(ctx context.Context, host string) (func(), error) {
	if g == nil {
		return func() {}, nil
	}
	if err := g.rate.Wait(ctx); err != nil {
		return nil, err
	}
	hostKey, limit := g.retainHost(host)
	if err := limit.rate.Wait(ctx); err != nil {
		g.releaseHost(hostKey, limit)
		return nil, err
	}
	select {
	case g.global <- struct{}{}:
	case <-ctx.Done():
		g.releaseHost(hostKey, limit)
		return nil, ctx.Err()
	}
	select {
	case limit.semaphore <- struct{}{}:
		return func() {
			<-limit.semaphore
			g.releaseHost(hostKey, limit)
			<-g.global
		}, nil
	case <-ctx.Done():
		g.releaseHost(hostKey, limit)
		<-g.global
		return nil, ctx.Err()
	}
}

func (g *Governor) retainHost(host string) (string, *hostLimit) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cleanupIdleHostsLocked(now)
	limit := g.hosts[host]
	if limit == nil {
		limit = &hostLimit{
			semaphore: make(chan struct{}, g.perHost),
			rate:      newRateLimiter(g.hostRPS, g.perHost),
			lastUsed:  now,
		}
		g.hosts[host] = limit
	}
	limit.references++
	limit.lastUsed = now
	return host, limit
}

func (g *Governor) releaseHost(host string, limit *hostLimit) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if current := g.hosts[host]; current != limit {
		return
	}
	limit.references--
	limit.lastUsed = time.Now()
	if limit.references < 0 {
		limit.references = 0
	}
}

func (g *Governor) cleanupIdleHostsLocked(now time.Time) {
	if now.Sub(g.lastSweep) < hostLimiterSweepInterval {
		return
	}
	for host, limit := range g.hosts {
		if limit.references == 0 && len(limit.semaphore) == 0 && now.Sub(limit.lastUsed) >= hostLimiterIdleTTL {
			delete(g.hosts, host)
		}
	}
	g.lastSweep = now
}
