package callback

import (
	"context"
	"testing"
	"time"
)

func TestCallbackIsOneTimeAndConsumed(t *testing.T) {
	registry := New()
	defer registry.Close()
	token, _ := registry.Register("http://127.0.0.1:61166", "test")
	if !registry.Hit(token) || registry.Hit(token) {
		t.Fatal("callback token must accept exactly one hit")
	}
	if !registry.Wait(context.Background(), token, time.Second) {
		t.Fatal("first hit was not observable")
	}
	if registry.Wait(context.Background(), token, time.Millisecond) {
		t.Fatal("consumed token remained observable")
	}
}

func TestExpiredCallbackRejected(t *testing.T) {
	registry := New()
	defer registry.Close()
	token, _ := registry.Register("http://127.0.0.1:61166", "test")
	registry.mu.Lock()
	registry.entries[token].expires = time.Now().Add(-time.Second)
	registry.mu.Unlock()
	if registry.Hit(token) {
		t.Fatal("expired token accepted")
	}
}

func TestRawTokenLookupAndConnectionLimit(t *testing.T) {
	registry := NewWithLimit(3)
	defer registry.Close()
	if cap(registry.rawConnections) != 3 {
		t.Fatalf("raw callback connection limit=%d", cap(registry.rawConnections))
	}
	token, _ := registry.Register("ldap://127.0.0.1:61167", "jndi")
	if registry.HitFromBytes([]byte("noise jhs-unknown-0123456789abcdef01234567")) {
		t.Fatal("unknown token was accepted")
	}
	if !registry.HitFromBytes([]byte("cn=" + token + ",dc=test")) {
		t.Fatal("registered token embedded in LDAP bytes was not found")
	}
	if !registry.Wait(context.Background(), token, time.Second) {
		t.Fatal("raw callback hit was not observable")
	}
}

func TestRegistryBoundsPendingEntriesAndCleansInBackground(t *testing.T) {
	registry := newRegistry(1, 2, 20*time.Millisecond, 5*time.Millisecond)
	defer registry.Close()
	first, _ := registry.Register("http://127.0.0.1:61166", "test")
	_, _ = registry.Register("http://127.0.0.1:61166", "test")
	_, _ = registry.Register("http://127.0.0.1:61166", "test")
	registry.mu.Lock()
	pending := len(registry.entries)
	if pending != 2 {
		registry.mu.Unlock()
		t.Fatalf("pending callback bound not enforced: %d", pending)
	}
	_, firstStillPresent := registry.entries[first]
	registry.mu.Unlock()
	if firstStillPresent {
		t.Fatal("oldest pending callback was not evicted")
	}
	time.Sleep(60 * time.Millisecond)
	registry.mu.Lock()
	remaining := len(registry.entries)
	registry.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("background cleanup left %d expired callbacks", remaining)
	}
	registry.Close()
	registry.mu.Lock()
	remaining = len(registry.entries)
	registry.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("Close retained %d pending callbacks", remaining)
	}
	registry.Close()
}

func TestRegisterSanitizesKindAndValidTokenIsStrict(t *testing.T) {
	registry := New()
	defer registry.Close()
	token, _ := registry.Register("http://127.0.0.1:61166", "XXE / unsafe")
	if !ValidToken(token) {
		t.Fatalf("generated token is invalid: %q", token)
	}
	for _, invalid := range []string{"", token + "/extra", "prefix-" + token, token + "?x=1"} {
		if ValidToken(invalid) {
			t.Fatalf("malformed token accepted: %q", invalid)
		}
	}
}

func TestTokenExtractionAndResponseMarker(t *testing.T) {
	registry := New()
	defer registry.Close()
	token, _ := registry.Register("http://127.0.0.1:61166", "ssrf")
	path := "/api/v1/callback/" + token + "/openapi/v1/envs/apps/1"
	tokens := TokensFromText(path)
	if len(tokens) != 1 || tokens[0] != token {
		t.Fatalf("embedded callback token was not extracted: %#v", tokens)
	}
	marker := ResponseMarker(token)
	if marker == "" || marker == token || ResponseMarker(token) != marker {
		t.Fatalf("callback response marker is not stable and distinct: token=%q marker=%q", token, marker)
	}
	if len(TokensFromText(marker)) != 0 {
		t.Fatalf("response marker must not be interpreted as a callback token: %q", marker)
	}
}

func TestCloseUnblocksWait(t *testing.T) {
	registry := New()
	token, _ := registry.Register("http://127.0.0.1:61166", "test")
	done := make(chan bool, 1)
	go func() { done <- registry.Wait(context.Background(), token, time.Hour) }()
	registry.Close()
	select {
	case hit := <-done:
		if hit {
			t.Fatal("registry close was reported as a callback hit")
		}
	case <-time.After(time.Second):
		t.Fatal("registry close did not unblock Wait")
	}
}
