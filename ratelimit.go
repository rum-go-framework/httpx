package httpx

import (
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// defaultMaxKeys bounds memory: one entry per distinct key, so the cap limits
// what a flood of rotating keys can cost.
const defaultMaxKeys = 10_000

type counter struct {
	count int
	reset time.Time
}

// RateLimiter is an in-memory fixed-window limiter, meant to throttle things
// like login attempts. It is one layer, not a credential-stuffing defense: an
// attacker spread over many networks or targeting many accounts is not
// stopped by a per-key limit.
//
// State is per process: with N replicas the effective limit is N times
// higher; use a shared store if you need a global limit.
//
// Memory is capped at the configured number of keys (see WithMaxKeys). An
// entry whose window is still active is never evicted, otherwise flooding
// new keys would reset counters and bypass the limit. Instead, once the cap
// is reached and no window has expired, new keys are denied (fail closed)
// until windows expire. Trade-off: a flood of that many distinct keys (for
// ClientIP, /64s) can deny new clients for up to one window, but cannot
// reset anyone's counter; keys already tracked keep working.
type RateLimiter struct {
	limit   int
	window  time.Duration
	maxKeys int
	now     func() time.Time

	mu        sync.Mutex
	keys      map[string]*counter
	lastSweep time.Time
	minReset  time.Time // lower bound on the earliest reset in keys
}

// RateLimiterOption configures a RateLimiter.
type RateLimiterOption func(*RateLimiter)

// WithMaxKeys sets how many distinct keys are tracked (default 10000).
// Non-positive values are ignored.
func WithMaxKeys(n int) RateLimiterOption {
	return func(rl *RateLimiter) {
		if n > 0 {
			rl.maxKeys = n
		}
	}
}

// NewRateLimiter allows limit requests per key in each window.
func NewRateLimiter(limit int, window time.Duration, opts ...RateLimiterOption) *RateLimiter {
	rl := &RateLimiter{
		limit:   limit,
		window:  window,
		maxKeys: defaultMaxKeys,
		now:     time.Now,
		keys:    make(map[string]*counter),
	}
	for _, opt := range opts {
		opt(rl)
	}
	return rl
}

// Allow records a request for key. When denied, retryAfter is the time left
// until the key's window resets, or the whole window if the limiter is full
// and key is new.
func (rl *RateLimiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	if now.Sub(rl.lastSweep) >= rl.window {
		rl.lastSweep = now
		rl.sweep(now)
	}

	w, found := rl.keys[key]
	if !found && len(rl.keys) >= rl.maxKeys {
		// Sweep only when something can have expired, so a flood of new keys
		// at capacity does not cost an O(n) scan per request.
		if now.Before(rl.minReset) {
			return false, rl.window
		}
		rl.sweep(now)
		if len(rl.keys) >= rl.maxKeys {
			return false, rl.window
		}
	}
	if !found || !now.Before(w.reset) {
		reset := now.Add(rl.window)
		if len(rl.keys) == 0 || reset.Before(rl.minReset) {
			rl.minReset = reset
		}
		rl.keys[key] = &counter{count: 1, reset: reset}
		return true, 0
	}
	if w.count >= rl.limit {
		return false, w.reset.Sub(now)
	}
	w.count++
	return true, 0
}

// sweep drops expired windows, so idle keys are freed without a background
// goroutine to leak or stop, and recomputes minReset.
func (rl *RateLimiter) sweep(now time.Time) {
	rl.minReset = time.Time{}
	for k, w := range rl.keys {
		if !now.Before(w.reset) {
			delete(rl.keys, k)
		} else if rl.minReset.IsZero() || w.reset.Before(rl.minReset) {
			rl.minReset = w.reset
		}
	}
}

// Middleware rejects over-limit requests with 429 and a Retry-After header
// (seconds). key identifies the caller; nil means ClientIP.
func (rl *RateLimiter) Middleware(key func(*http.Request) string) func(http.Handler) http.Handler {
	if key == nil {
		key = ClientIP
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok, retry := rl.Allow(key(r))
			if ok {
				next.ServeHTTP(w, r)
				return
			}
			secs := int(math.Ceil(retry.Seconds()))
			w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		})
	}
}

// ClientIP returns the rate-limit key for r.RemoteAddr: the IPv4 address, or
// for IPv6 its /64 prefix, since a single host normally controls a whole /64
// and per-address keys would be free to mint. IPv4-mapped IPv6 addresses count
// as IPv4. It does not trust forwarding headers. Behind a proxy, rewrite
// RemoteAddr from the X-Forwarded-For entry appended by your outermost trusted
// proxy (counting from the right) before this runs. Avoid chi's RealIP here:
// it trusts the leftmost entry, which the client controls.
func ClientIP(r *http.Request) string {
	host := remoteHost(r)
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if addr = addr.Unmap(); addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

// remoteHost is the host part of r.RemoteAddr, unmasked.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
