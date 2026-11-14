package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var ok200 = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

func do(h http.Handler, method, target string, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestDecodeJSONBody(t *testing.T) {
	type in struct{ A int }
	tests := []struct {
		name, ct, body string
		limit          int64
		status         int // 0 = success
	}{
		{"ok", "application/json; charset=utf-8", `{"A":1}`, 100, 0},
		{"no content type", "", `{"A":1}`, 100, 0},
		{"wrong type", "text/plain", `{"A":1}`, 100, 415},
		{"unknown field", "", `{"B":1}`, 100, 400},
		{"trailing", "", `{"A":1}{"A":2}`, 100, 400},
		{"empty", "", ``, 100, 400},
		{"syntax", "", `{"A":`, 100, 400},
		{"bad type", "", `{"A":"x"}`, 100, 400},
		{"too large", "", `{"A":1}`, 3, 413},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", strings.NewReader(tt.body))
			if tt.ct != "" {
				r.Header.Set("Content-Type", tt.ct)
			}
			var dst in
			err := DecodeJSONBodyLimit(httptest.NewRecorder(), r, &dst, tt.limit)
			if tt.status == 0 {
				if err != nil || dst.A != 1 {
					t.Fatalf("err=%v dst=%+v", err, dst)
				}
				return
			}
			var mr *MalformedRequest
			if !errors.As(err, &mr) || mr.Status != tt.status {
				t.Fatalf("got %v, want status %d", err, tt.status)
			}
		})
	}
}

func TestJSONResponse(t *testing.T) {
	w := httptest.NewRecorder()
	JSONResponse(w, "created", map[string]int{"id": 1}, 201, 7)
	var got Response
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if w.Code != 201 || !got.Status || got.Code != 201 || got.ResponseCode != 7 {
		t.Fatalf("code=%d resp=%+v", w.Code, got)
	}

	w = httptest.NewRecorder()
	JSONResponse(w, "nope", nil, 404)
	if w.Code != 404 || strings.Contains(w.Body.String(), `"status":true`) {
		t.Fatalf("code=%d body=%s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	JSONResponse(w, "bad", make(chan int))
	if w.Code != 500 {
		t.Fatalf("unmarshalable data: code=%d", w.Code)
	}
}

func TestHealth(t *testing.T) {
	down := errors.New("db down")
	h := Health(
		Probe{Path: LivenessPath},
		Probe{Path: ReadinessPath, Check: func(context.Context) error { return down }},
	)(ok200)

	if w := do(h, "GET", "/livez/", nil); w.Code != 200 {
		t.Fatalf("liveness %d", w.Code)
	}
	if w := do(h, "HEAD", "/HEALTHZ", nil); w.Code != 503 {
		t.Fatalf("readiness %d", w.Code)
	}
	if w := do(h, "POST", "/livez", nil); w.Body.String() != "ok" {
		t.Fatal("POST must fall through")
	}
	if w := do(h, "GET", "/other", nil); w.Body.String() != "ok" {
		t.Fatal("other path must fall through")
	}
}

func TestRateLimiterWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	rl := NewRateLimiter(2, time.Minute)
	rl.now = func() time.Time { return now }

	for i := range 2 {
		if ok, _ := rl.Allow("a"); !ok {
			t.Fatalf("request %d denied", i)
		}
	}
	ok, retry := rl.Allow("a")
	if ok || retry != time.Minute {
		t.Fatalf("ok=%v retry=%v", ok, retry)
	}
	if ok, _ := rl.Allow("b"); !ok {
		t.Fatal("keys must be independent")
	}
	now = now.Add(time.Minute)
	if ok, _ := rl.Allow("a"); !ok {
		t.Fatal("window should have reset")
	}
}

func TestRateLimiterBoundedMemory(t *testing.T) {
	now := time.Unix(1000, 0)
	rl := NewRateLimiter(1, time.Minute)
	rl.now = func() time.Time { return now }

	for i := range maxKeys + 500 {
		rl.Allow("k" + strconv.Itoa(i))
	}
	if len(rl.keys) > maxKeys {
		t.Fatalf("keys=%d exceeds cap", len(rl.keys))
	}
	now = now.Add(2 * time.Minute)
	rl.Allow("fresh")
	if len(rl.keys) != 1 {
		t.Fatalf("idle keys not swept: %d", len(rl.keys))
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	h := NewRateLimiter(1, time.Minute).Middleware(nil)(ok200)
	ip := func(addr string) func(*http.Request) { return func(r *http.Request) { r.RemoteAddr = addr } }

	if w := do(h, "GET", "/", ip("10.0.0.1:1111")); w.Code != 200 {
		t.Fatalf("first: %d", w.Code)
	}
	w := do(h, "GET", "/", ip("10.0.0.1:2222")) // new port, same client
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("code=%d retry=%q", w.Code, w.Header().Get("Retry-After"))
	}
	if w := do(h, "GET", "/", ip("[2001:db8::1]:80")); w.Code != 200 {
		t.Fatalf("ipv6 client: %d", w.Code)
	}
	if w := do(h, "GET", "/", ip("[2001:db8::2]:80")); w.Code != 200 {
		t.Fatal("ipv6 clients must not collapse into one key")
	}
}

func TestSecurityHeaders(t *testing.T) {
	w := do(SecurityHeaders(SecurityHeadersConfig{})(ok200), "GET", "/", nil)
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%v", w.Header())
	}
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must be opt-in")
	}

	cfg := SecurityHeadersConfig{HSTSMaxAge: time.Hour, HSTSIncludeSubdomains: true}
	w = do(SecurityHeaders(cfg)(ok200), "GET", "/", nil)
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=3600; includeSubDomains" {
		t.Fatalf("hsts=%q", got)
	}
}

func TestRequestLogger(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := RequestLogger(log)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("abc"))
	}))
	do(h, "GET", "/x", nil)

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["status"] != float64(418) || rec["bytes"] != float64(3) || rec["path"] != "/x" {
		t.Fatalf("%v", rec)
	}
}
