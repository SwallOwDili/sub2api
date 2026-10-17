package chatgptnetwork

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// A persisted UI setting takes precedence over the legacy environment fallback.
var runtimeValue atomic.Pointer[bool]

var persistedPolicy atomic.Pointer[policyCache]

// ConfigureSource keeps every process synchronized with persisted settings.
// Reads are bounded and cached; storage failures retain the last known policy.
func ConfigureSource(initial bool, load func(context.Context) (bool, error)) {
	p := &policyCache{value: initial, load: load, next: time.Now().Add(5 * time.Second)}
	persistedPolicy.Store(p)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		p.watch(ticker.C)
	}()
}

type policyCache struct {
	mu         sync.Mutex
	value      bool
	next       time.Time
	load       func(context.Context) (bool, error)
	refreshing bool
	version    uint64
}

// Poll even without traffic so an idle instance adopts remote saves.
func (p *policyCache) watch(ticks <-chan time.Time) {
	for range ticks {
		if persistedPolicy.Load() != p {
			return
		}
		p.mu.Lock()
		if !p.refreshing {
			p.refreshing = true
			go p.refresh(p.version)
		}
		p.mu.Unlock()
	}
}
func (p *policyCache) get() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !time.Now().Before(p.next) && !p.refreshing {
		p.refreshing = true
		go p.refresh(p.version)
	}
	return p.value
}
func (p *policyCache) refresh(version uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	value, err := p.load(ctx)
	cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	// A local save that happened during the read must win over the stale result.
	if version == p.version {
		if err == nil {
			p.value = value
		}
		p.next = time.Now().Add(5 * time.Second)
	}
	p.refreshing = false
}
func SetEnabled(enabled bool) {
	if p := persistedPolicy.Load(); p != nil {
		p.mu.Lock()
		p.version++
		p.value = enabled
		p.next = time.Now().Add(5 * time.Second)
		p.mu.Unlock()
	}
	runtimeValue.Store(&enabled)
}
func Enabled() bool {
	if p := persistedPolicy.Load(); p != nil {
		return p.get()
	}
	if value := runtimeValue.Load(); value != nil {
		return *value
	}
	return DefaultEnabled()
}

type transport struct {
	configure func(*http.Transport) error
	initErr   error
	base      *http.Transport
	proxy     bool
	mu        sync.Mutex
	ipv6      *http.Transport
}

// Wrap keeps separate pools so toggling cannot reuse an opposite-family socket.
// Existing in-flight requests finish normally. Other hosts always use base.
func Wrap(base *http.Transport, proxy bool, configure ...func(*http.Transport) error) http.RoundTripper {
	t := &transport{base: base, proxy: proxy}
	if len(configure) > 0 {
		t.configure = configure[0]
	}
	return t
}
func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !isChatGPT(r.URL.Hostname()) || !enabledForContext(r.Context()) {
		return t.base.RoundTrip(r)
	}
	t.mu.Lock()
	if t.ipv6 == nil {
		t.ipv6 = t.base.Clone()
		applyIPv6(t.ipv6, t.proxy, nil)
		if t.configure != nil {
			t.initErr = t.configure(t.ipv6)
		}
	}
	v6 := t.ipv6
	err := t.initErr
	t.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return v6.RoundTrip(r)
}
func (t *transport) CloseIdleConnections() {
	t.base.CloseIdleConnections()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ipv6 != nil {
		t.ipv6.CloseIdleConnections()
	}
}
func BaseTransport(rt http.RoundTripper) (*http.Transport, bool) {
	if t, ok := rt.(*transport); ok {
		return t.base, true
	}
	t, ok := rt.(*http.Transport)
	return t, ok
}

func DefaultEnabled() bool { enabled, _ := strconv.ParseBool(os.Getenv(EnvIPv6Only)); return enabled }

type policyContextKey struct{}

// WithPolicy pins the mode for a pooled WebSocket handshake, including prewarm.
func WithPolicy(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, policyContextKey{}, enabled)
}
func enabledForContext(ctx context.Context) bool {
	if v, ok := ctx.Value(policyContextKey{}).(bool); ok {
		return v
	}
	return Enabled()
}
func EnabledForURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && isChatGPT(u.Hostname()) && Enabled()
}
