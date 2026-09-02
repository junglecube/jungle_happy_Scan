package callback

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TokensFromText extracts callback tokens embedded in a longer URL path,
// query string or protocol payload. Registry lookup remains the final
// authorization check, so an unregistered token can never create a hit.
func TokensFromText(value string) []string {
	return tokenPattern.FindAllString(value, -1)
}

// ResponseMarker is deliberately absent from the callback URL. If it appears
// in the scanned application's response, the application fetched the callback
// response rather than merely reflecting the injected URL.
func ResponseMarker(token string) string {
	sum := sha256.Sum256([]byte("jungle-happy-scan-callback-response\x00" + token))
	return "jungle-callback-response-" + hex.EncodeToString(sum[:12])
}

var (
	tokenPattern = regexp.MustCompile(`(?i)jhs-[a-z0-9_-]+-[0-9a-f]{24}`)
	kindPattern  = regexp.MustCompile(`[^a-z0-9_-]+`)
)

const (
	defaultMaxPending      = 8192
	defaultEntryTTL        = 10 * time.Minute
	defaultCleanupInterval = time.Minute
)

type entry struct {
	hit     chan struct{}
	expires time.Time
	once    sync.Once
	seen    bool
}

// HitFromBytes is used by the minimal LDAP/JNDI TCP sink. It only recognizes
// an already registered random token and never returns classes or serialized
// objects to the target.
func (r *Registry) HitFromBytes(data []byte) bool {
	now := time.Now()
	tokens := tokenPattern.FindAllString(string(data), -1)
	if len(tokens) == 0 {
		return false
	}
	r.mu.Lock()
	for _, token := range tokens {
		item := r.entries[token]
		if item == nil {
			continue
		}
		if now.After(item.expires) {
			delete(r.entries, token)
			continue
		}
		if item.seen {
			continue
		}
		item.seen = true
		r.mu.Unlock()
		item.once.Do(func() { close(item.hit) })
		return true
	}
	r.mu.Unlock()
	return false
}

// ServeRaw accepts LDAP/JNDI connection attempts, reads only enough bytes to
// find the one-time token, and closes the connection without serving content.
func (r *Registry) ServeRaw(listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case r.rawConnections <- struct{}{}:
		default:
			_ = connection.Close()
			continue
		}
		go func() {
			defer func() { <-r.rawConnections }()
			defer connection.Close()
			_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
			buffer := make([]byte, 16_384)
			read, _ := connection.Read(buffer)
			if read > 0 && r.HitFromBytes(buffer[:read]) {
				return
			}
			// Minimal anonymous LDAP bind success, only to let the client send the
			// search DN that carries our token. No search entry or class is served.
			_, _ = connection.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
			read, _ = connection.Read(buffer)
			if read > 0 {
				r.HitFromBytes(buffer[:read])
			}
		}()
	}
}

type Registry struct {
	mu             sync.Mutex
	entries        map[string]*entry
	rawConnections chan struct{}
	maxPending     int
	entryTTL       time.Duration
	stop           chan struct{}
	done           chan struct{}
	closeOnce      sync.Once
	closed         bool
}

func New() *Registry { return NewWithLimit(128) }

func NewWithLimit(maxRawConnections int) *Registry {
	return NewWithLimits(maxRawConnections, defaultMaxPending)
}

// NewWithLimits keeps both the raw callback concurrency and the number of
// outstanding one-time tokens bounded. New and NewWithLimit retain their
// original API and use a conservative default pending-token limit.
func NewWithLimits(maxRawConnections, maxPending int) *Registry {
	return newRegistry(maxRawConnections, maxPending, defaultEntryTTL, defaultCleanupInterval)
}

func newRegistry(maxRawConnections, maxPending int, entryTTL, cleanupInterval time.Duration) *Registry {
	if maxRawConnections < 1 {
		maxRawConnections = 1
	}
	if maxPending < 1 {
		maxPending = 1
	}
	if entryTTL <= 0 {
		entryTTL = defaultEntryTTL
	}
	if cleanupInterval <= 0 {
		cleanupInterval = defaultCleanupInterval
	}
	r := &Registry{
		entries:        make(map[string]*entry),
		rawConnections: make(chan struct{}, maxRawConnections),
		maxPending:     maxPending,
		entryTTL:       entryTTL,
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}
	go r.cleanupLoop(cleanupInterval)
	return r
}

func (r *Registry) Register(baseURL, kind string) (string, string) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	kind = kindPattern.ReplaceAllString(kind, "-")
	kind = strings.Trim(kind, "-")
	if kind == "" {
		kind = "callback"
	}
	if len(kind) > 32 {
		kind = kind[:32]
	}
	random := make([]byte, 12)
	_, _ = rand.Read(random)
	token := "jhs-" + kind + "-" + hex.EncodeToString(random)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return token, strings.TrimRight(baseURL, "/") + "/api/v1/callback/" + token
	}
	r.cleanupLocked(time.Now())
	for len(r.entries) >= r.maxPending {
		r.evictOldestLocked()
	}
	r.entries[token] = &entry{hit: make(chan struct{}), expires: time.Now().Add(r.entryTTL)}
	r.mu.Unlock()
	return token, strings.TrimRight(baseURL, "/") + "/api/v1/callback/" + token
}

// ValidToken performs the same strict full-token validation used by the
// registry. HTTP handlers should reject malformed paths before doing a lookup.
func ValidToken(token string) bool {
	return token != "" && len(token) <= 128 && tokenPattern.FindString(token) == token
}

func (r *Registry) Hit(token string) bool {
	if !ValidToken(token) {
		return false
	}
	r.mu.Lock()
	item := r.entries[token]
	if item == nil || time.Now().After(item.expires) || item.seen {
		if item != nil && time.Now().After(item.expires) {
			delete(r.entries, token)
		}
		r.mu.Unlock()
		return false
	}
	item.seen = true
	r.mu.Unlock()
	item.once.Do(func() { close(item.hit) })
	return true
}

func (r *Registry) Wait(ctx context.Context, token string, timeout time.Duration) bool {
	r.mu.Lock()
	item := r.entries[token]
	if item != nil && time.Now().After(item.expires) {
		delete(r.entries, token)
		item = nil
	}
	r.mu.Unlock()
	if item == nil {
		return false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-item.hit:
		r.mu.Lock()
		delete(r.entries, token)
		r.mu.Unlock()
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	case <-r.stop:
		return false
	}
}

// WaitBatch observes many one-time probes with one ticker instead of creating
// one goroutine and timer per payload. Unseen tokens remain registered until
// their TTL so a later diagnostic callback can still be recognized.
func (r *Registry) WaitBatch(ctx context.Context, tokens []string, timeout time.Duration) map[string]bool {
	result := make(map[string]bool, len(tokens))
	pending := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		if ValidToken(token) {
			pending[token] = struct{}{}
		}
	}
	consume := func() {
		now := time.Now()
		r.mu.Lock()
		for token := range pending {
			item := r.entries[token]
			if item == nil {
				delete(pending, token)
				continue
			}
			if now.After(item.expires) {
				delete(r.entries, token)
				delete(pending, token)
				continue
			}
			if item.seen {
				result[token] = true
				delete(r.entries, token)
				delete(pending, token)
			}
		}
		r.mu.Unlock()
	}
	consume()
	if len(pending) == 0 {
		return result
	}
	timer := time.NewTimer(timeout)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer timer.Stop()
	defer ticker.Stop()
	for len(pending) > 0 {
		select {
		case <-ticker.C:
			consume()
		case <-timer.C:
			consume()
			return result
		case <-ctx.Done():
			return result
		case <-r.stop:
			return result
		}
	}
	return result
}

func (r *Registry) cleanup() {
	now := time.Now()
	r.mu.Lock()
	r.cleanupLocked(now)
	r.mu.Unlock()
}

func (r *Registry) cleanupLocked(now time.Time) {
	for token, item := range r.entries {
		if now.After(item.expires) {
			delete(r.entries, token)
		}
	}
}

func (r *Registry) evictOldestLocked() {
	var oldestToken string
	var oldestExpiry time.Time
	for token, item := range r.entries {
		if oldestToken == "" || item.expires.Before(oldestExpiry) {
			oldestToken, oldestExpiry = token, item.expires
		}
	}
	if oldestToken != "" {
		delete(r.entries, oldestToken)
	}
}

func (r *Registry) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
		close(r.done)
	}()
	for {
		select {
		case <-ticker.C:
			r.cleanup()
		case <-r.stop:
			return
		}
	}
}

// Close stops the registry's background cleanup worker. It is idempotent.
func (r *Registry) Close() {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		close(r.stop)
	})
	<-r.done
	r.mu.Lock()
	clear(r.entries)
	r.mu.Unlock()
}
