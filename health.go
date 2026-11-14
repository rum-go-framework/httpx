package httpx

import (
	"context"
	"net/http"
	"strings"
)

// Conventional Kubernetes-style probe paths.
const (
	LivenessPath  = "/livez"
	ReadinessPath = "/healthz"
	StartupPath   = "/startupz"
)

// Check reports whether a dependency is healthy; a non-nil error means down.
type Check func(ctx context.Context) error

// Probe binds a path to a Check. A nil Check always reports healthy, which is
// what a liveness probe wants.
type Probe struct {
	Path  string
	Check Check
}

// Health answers GET/HEAD requests on the probes' paths (trailing slash and
// case ignored) with 200, or 503 when the Check fails. Everything else falls
// through. Put it before logging/auth middleware so probes stay cheap and
// unauthenticated. Failure details are not exposed to the caller.
func Health(probes ...Probe) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			p, ok := findProbe(probes, r.URL.Path)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			if p.Check != nil && p.Check(r.Context()) != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
	}
}

func findProbe(probes []Probe, path string) (Probe, bool) {
	path = strings.TrimSuffix(path, "/")
	for _, p := range probes {
		if strings.EqualFold(path, p.Path) {
			return p, true
		}
	}
	return Probe{}, false
}
