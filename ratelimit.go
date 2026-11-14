package httpx

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// maxKeys bounds memory: one entry per distinct key, so the cap limits what a
// flood of spoofed or rotating keys can cost.
const maxKeys = 10_000

type counter struct {
	count int
	reset time.Time
}

// RateLimiter is an in-memory fixed-window limiter. State is per process;
// run behind a shared store if you need a limit across replicas.
type RateLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]*counter
	lastSweep time.Time
}

// NewRateLimiter allows limit requests per key in each window.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:  limit,
		window: window,
		now:    time.Now,
		keys:   make(map[string]*counter),
	}
}

// Allow records a request for key. When denied, retryAfter is the time left
// until the key's window resets.
func (rl *RateLimiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	rl.sweep(now)

	w, found := rl.keys[key]
	if !found || !now.Before(w.reset) {
		rl.makeRoom(found)
		rl.keys[key] = &counter{count: 1, reset: now.Add(rl.window)}
		return true, 0
	}
	if w.count >= rl.limit {
		return false, w.reset.Sub(now)
	}
	w.count++
	return true, 0
}

// sweep drops expired windows at most once per window, so idle keys are
// freed without a background goroutine to leak or stop.
func (rl *RateLimiter) sweep(now time.Time) {
	if now.Sub(rl.lastSweep) < rl.window {
		return
	}
	rl.lastSweep = now
	for k, w := range rl.keys {
		if !now.Before(w.reset) {
			delete(rl.keys, k)
		}
	}
}

// makeRoom evicts an arbitrary entry when a new key would exceed maxKeys.
// Map order is random, so an attacker cannot target a victim's entry.
func (rl *RateLimiter) makeRoom(replacing bool) {
	if replacing || len(rl.keys) < maxKeys {
		return
	}
	for k := range rl.keys {
		delete(rl.keys, k)
		return
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

// ClientIP returns the host part of r.RemoteAddr. It does not trust
// forwarding headers: install chi's RealIP first if you sit behind a proxy.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
