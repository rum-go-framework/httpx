package httpx

import (
	"net/http"
	"strconv"
	"time"
)

// SecurityHeadersConfig tunes SecurityHeaders. The zero value is a sane
// default.
type SecurityHeadersConfig struct {
	// FrameOptions defaults to "DENY".
	FrameOptions string
	// ReferrerPolicy defaults to "origin-when-cross-origin".
	ReferrerPolicy string
	// ContentSecurityPolicy is omitted when empty.
	ContentSecurityPolicy string
	// HSTSMaxAge enables Strict-Transport-Security when positive. Leave it
	// zero over plain HTTP and in development.
	HSTSMaxAge time.Duration
	// HSTSIncludeSubdomains adds includeSubDomains to the HSTS header.
	HSTSIncludeSubdomains bool
}

// SecurityHeaders sets common response hardening headers before calling next.
func SecurityHeaders(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	h := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        orDefault(cfg.FrameOptions, "DENY"),
		"Referrer-Policy":        orDefault(cfg.ReferrerPolicy, "origin-when-cross-origin"),
		// Legacy XSS auditors introduce vulnerabilities; 0 turns them off.
		"X-XSS-Protection": "0",
	}
	if cfg.ContentSecurityPolicy != "" {
		h["Content-Security-Policy"] = cfg.ContentSecurityPolicy
	}
	if cfg.HSTSMaxAge > 0 {
		v := "max-age=" + strconv.Itoa(int(cfg.HSTSMaxAge.Seconds()))
		if cfg.HSTSIncludeSubdomains {
			v += "; includeSubDomains"
		}
		h["Strict-Transport-Security"] = v
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr := w.Header()
			for k, v := range h {
				hdr.Set(k, v)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
